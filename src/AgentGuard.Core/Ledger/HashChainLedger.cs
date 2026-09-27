using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentGuard.Core.Ledger;

/// <summary>
/// A tamper-evident, in-memory <see cref="IGuardrailLedger"/>. Every appended decision is
/// stamped into a SHA-256 hash chain: each entry hashes its own fields together with the
/// previous entry's hash, so any retroactive mutation breaks the chain and is detected by
/// <see cref="Verify()"/>. Optionally mirrors each entry to an append-only JSONL file.
/// Dependency-free (<see cref="System.Security.Cryptography"/> + <see cref="System.Text.Json"/>).
/// </summary>
/// <remarks>
/// <para>
/// Thread-safe. Appends are serialized (the chain is sequential) while reads
/// (<see cref="Entries"/>, <see cref="Count"/>, <see cref="Verify()"/>, <see cref="Export"/>)
/// take only a brief lock so they are not blocked while a writer computes its SHA-256 hash.
/// </para>
/// <para>
/// <b>Restarts.</b> A ledger created over a JSONL file that already holds entries continues that
/// chain: its first entry follows the file's last one in sequence and links to that entry's hash,
/// so the file stays one chain that <see cref="Load"/> verifies from genesis. The entries held in
/// memory then start mid-chain.
/// </para>
/// <para>
/// <b>What tamper-evidence covers.</b> Editing an entry, or removing one from the middle of the
/// chain, breaks the linkage and is reported by <see cref="Verify()"/>. Removing entries from the
/// <i>end</i> is not detectable: a hash chain carries no record of how long it should be, so a
/// truncated chain is indistinguishable from one that simply stopped there. Detecting that needs an
/// external anchor - the last sequence number recorded somewhere the chain's holder cannot reach,
/// or periodic publication of the head hash.
/// </para>
/// </remarks>
public sealed class HashChainLedger : IGuardrailLedger, IDisposable
{
    // a line longer than this is not a ledger entry, so continuing a chain never reads more of the file
    private const int MaxEntryBytes = 64 * 1024 * 1024;

    private readonly List<GuardrailLedgerEntry> _entries = [];

    // the hash chain is sequential, so appends must serialize; _appendLock is held for
    // the whole append (including the JSONL file write, so persisted order matches the
    // chain). _entriesLock guards the list itself and is held only briefly so readers
    // are not blocked while a writer is busy hashing.
    private readonly object _appendLock = new();
    private readonly object _entriesLock = new();

    private readonly string? _jsonlPath;
    private readonly StreamWriter? _writer;
    private readonly int? _maxInMemoryEntries;

    // the chain position of the first entry the retained list can hold, and the hash that entry links
    // to. Non-zero means the list is a window that starts mid-chain: older entries were evicted under
    // the in-memory cap, or the ledger continues a chain an earlier instance persisted.
    private long _trimmed;
    private string _lastTrimmedHash = string.Empty;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly JsonSerializerOptions JsonLineOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly JsonSerializerOptions JsonReadOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Creates a ledger.
    /// </summary>
    /// <param name="jsonlFilePath">
    /// When provided, each appended entry is also written as one JSON object per line
    /// (JSONL) to this append-only file. The containing directory is created eagerly if
    /// it does not already exist, so the first append cannot fail on a missing directory.
    /// When the file already holds entries, for example ones written before a process restart, the
    /// ledger continues that chain: the next entry's <see cref="GuardrailLedgerEntry.Seq"/> follows the
    /// file's last entry and its <see cref="GuardrailLedgerEntry.PreviousHash"/> is that entry's
    /// <see cref="GuardrailLedgerEntry.Hash"/>. Only the last line of the file is read, so
    /// <see cref="Entries"/> holds just the entries appended since, and <see cref="Verify()"/> checks
    /// that they link to the persisted tail. Use <see cref="Load"/> to verify the whole file.
    /// </param>
    /// <param name="maxInMemoryEntries">
    /// Caps how many entries are held in memory. When the cap is reached the oldest are evicted, so
    /// <see cref="Entries"/> and <see cref="Verify()"/> cover a trailing window rather than the
    /// whole chain; the JSONL file, when configured, still receives every entry. Null (the default)
    /// retains everything, which is only safe for a bounded run - a long-lived service accumulates
    /// one entry per guardrail decision for the life of the process.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxInMemoryEntries"/> is not positive.</exception>
    /// <exception cref="InvalidDataException">
    /// The last line of <paramref name="jsonlFilePath"/> is not an intact ledger entry (an incomplete
    /// write or an edit), so the chain cannot be continued from it.
    /// </exception>
    public HashChainLedger(string? jsonlFilePath = null, int? maxInMemoryEntries = null)
        : this(jsonlFilePath, maxInMemoryEntries, continuePersistedChain: true)
    {
    }

    private HashChainLedger(string? jsonlFilePath, int? maxInMemoryEntries, bool continuePersistedChain)
    {
        if (maxInMemoryEntries is <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxInMemoryEntries), "The cap must be greater than zero.");

        _jsonlPath = jsonlFilePath;
        _maxInMemoryEntries = maxInMemoryEntries;

        if (_jsonlPath is null)
            return;

        var dir = Path.GetDirectoryName(Path.GetFullPath(_jsonlPath));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var endsMidLine = false;
        if (File.Exists(_jsonlPath))
        {
            using var file = new FileStream(_jsonlPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            endsMidLine = file.Length > 0 && ReadLastByte(file) != '\n';

            // a second genesis in the same file would fork the chain, so continue from the last entry
            if (continuePersistedChain && ReadLastLine(file, _jsonlPath) is { } lastLine)
            {
                var last = ParseEntry(lastLine, _jsonlPath, "the last line");
                if (last.Seq < 0 || !HashMatches(last))
                {
                    throw new InvalidDataException(
                        $"Ledger file '{_jsonlPath}': the last entry does not match its hash, so the chain cannot be continued from it.");
                }

                _trimmed = last.Seq + 1;
                _lastTrimmedHash = last.Hash;
            }
        }

        // one handle held open for the life of the ledger, so an append never opens the file on the
        // guarded request's thread; FileShare.Read lets an auditor tail the file while it is being written.
        _writer = new StreamWriter(
            new FileStream(_jsonlPath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true
        };

        // every entry is one line, so an unterminated last line gets its line break before the next entry
        if (endsMidLine)
        {
            _writer.WriteLine();
        }
    }

    /// <summary>Flushes and closes the JSONL file handle, when one is configured.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        lock (_appendLock)
        {
            _writer?.Dispose();
        }
    }

    /// <summary>
    /// The number of entries held in memory - the whole chain unless older entries were evicted
    /// under the in-memory cap or the ledger continues a persisted chain.
    /// </summary>
    public int Count
    {
        get { lock (_entriesLock) { return _entries.Count; } }
    }

    /// <inheritdoc />
    public void Append(GuardrailDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);

        GuardrailLedgerEntry entry;
        lock (_appendLock)
        {
            long seq;
            string previousHash;
            lock (_entriesLock)
            {
                // the sequence counts the whole chain, not just what is still retained
                seq = _trimmed + _entries.Count;
                previousHash = _entries.Count == 0
                    ? (_trimmed == 0 ? string.Empty : _lastTrimmedHash)
                    : _entries[^1].Hash;
            }

            var hash = ComputeHash(seq, previousHash, decision);
            entry = new GuardrailLedgerEntry
            {
                Seq = seq,
                PreviousHash = previousHash,
                Hash = hash,
                Decision = decision
            };

            lock (_entriesLock)
            {
                _entries.Add(entry);

                if (_maxInMemoryEntries is { } cap && _entries.Count > cap)
                {
                    var excess = _entries.Count - cap;
                    _lastTrimmedHash = _entries[excess - 1].Hash;
                    _entries.RemoveRange(0, excess);
                    _trimmed += excess;
                }
            }

            // write the file inside the append lock so the JSONL line order always
            // matches the chain order (otherwise concurrent appends could interleave
            // file writes and make a later HashChainLedger.Load(...) verify as broken)
            _writer?.WriteLine(JsonSerializer.Serialize(entry, JsonLineOptions));
        }
    }

    /// <summary>
    /// A snapshot of the entries held in memory, in chain order. It starts mid-chain when older
    /// entries were evicted under the in-memory cap or the ledger continues a persisted chain.
    /// </summary>
    public IReadOnlyList<GuardrailLedgerEntry> Entries
    {
        get { lock (_entriesLock) { return _entries.ToArray(); } }
    }

    /// <summary>
    /// Recomputes the entries held in memory and verifies that every entry's hash and previous-hash
    /// linkage are intact. When they start mid-chain, the first one must link to the entry before
    /// it - the last evicted entry, or the last entry of the persisted chain this ledger continues.
    /// </summary>
    /// <returns><c>true</c> if the chain is intact; otherwise <c>false</c>.</returns>
    public bool Verify() => Verify(out _);

    /// <summary>
    /// Recomputes the entries held in memory and verifies their integrity, reporting the first
    /// broken entry when verification fails. See <see cref="Verify()"/>.
    /// </summary>
    /// <param name="brokenAtSeq">
    /// The <see cref="GuardrailLedgerEntry.Seq"/> of the first tampered entry, or -1 when
    /// the chain is intact.
    /// </param>
    /// <returns><c>true</c> if the chain is intact; otherwise <c>false</c>.</returns>
    public bool Verify(out long brokenAtSeq)
    {
        lock (_entriesLock)
        {
            // a window that starts mid-chain links to the entry before it rather than to genesis
            var expectedFirstPreviousHash = _trimmed == 0 ? string.Empty : _lastTrimmedHash;
            return VerifyChain(_entries, expectedFirstPreviousHash, out brokenAtSeq);
        }
    }

    /// <summary>
    /// Verifies an arbitrary, ordered sequence of ledger entries (for example one loaded
    /// from a persisted JSONL file via <see cref="Load"/>) without mutating any state.
    /// </summary>
    /// <param name="entries">The entries to verify, in chain (ascending <see cref="GuardrailLedgerEntry.Seq"/>) order.</param>
    /// <param name="brokenAtSeq">
    /// The <see cref="GuardrailLedgerEntry.Seq"/> of the first tampered entry, or -1 when
    /// the chain is intact.
    /// </param>
    /// <returns><c>true</c> if the chain is intact; otherwise <c>false</c>.</returns>
    public static bool Verify(IReadOnlyList<GuardrailLedgerEntry> entries, out long brokenAtSeq) =>
        Verify(entries, out brokenAtSeq, requireGenesis: true);

    /// <summary>
    /// Verifies an ordered sequence of ledger entries, optionally allowing it to start partway
    /// through a chain.
    /// </summary>
    /// <param name="entries">The entries to verify, in ascending <see cref="GuardrailLedgerEntry.Seq"/> order.</param>
    /// <param name="brokenAtSeq">The first tampered entry's sequence number, or -1 when intact.</param>
    /// <param name="requireGenesis">
    /// When true the first entry must be the chain's genesis (empty previous hash). Pass false to
    /// verify a trailing window, such as one retained under an in-memory cap; its first entry's own
    /// hash is still checked, but not what it links to.
    /// </param>
    /// <returns><c>true</c> if the sequence is intact; otherwise <c>false</c>.</returns>
    public static bool Verify(IReadOnlyList<GuardrailLedgerEntry> entries, out long brokenAtSeq, bool requireGenesis)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return VerifyChain(entries, requireGenesis ? string.Empty : null, out brokenAtSeq);
    }

    // expectedFirstPreviousHash is what the first entry must link to: empty for genesis, null when unknown
    private static bool VerifyChain(
        IReadOnlyList<GuardrailLedgerEntry> entries, string? expectedFirstPreviousHash, out long brokenAtSeq)
    {
        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var expectedPreviousHash = i == 0 ? expectedFirstPreviousHash : entries[i - 1].Hash;

            if ((expectedPreviousHash is not null && !StringsEqual(entry.PreviousHash, expectedPreviousHash))
                || !HashMatches(entry))
            {
                brokenAtSeq = entry.Seq;
                return false;
            }
        }

        brokenAtSeq = -1;
        return true;
    }

    /// <summary>
    /// Loads a ledger from an append-only JSONL file previously written by a ledger
    /// configured with a <c>jsonlFilePath</c>. The stored hashes are preserved as-is
    /// (not recomputed), so the returned ledger can be re-verified with <see cref="Verify()"/>
    /// after a process restart. The file is opened for shared reading, so it can be loaded while a
    /// running ledger is still appending to it.
    /// </summary>
    /// <param name="jsonlFilePath">Path to the JSONL file to load.</param>
    /// <param name="resumeWriting">
    /// When <c>true</c>, the returned ledger keeps writing to <paramref name="jsonlFilePath"/>,
    /// so appends extend the same persisted chain, as with a ledger constructed over the file, but
    /// with every persisted entry also held in memory. When <c>false</c> (the default) the
    /// returned ledger is in-memory only (verification-only) and does not write back.
    /// </param>
    /// <returns>A ledger populated with the persisted entries.</returns>
    /// <exception cref="InvalidDataException">A line of the file is not a valid ledger entry.</exception>
    public static HashChainLedger Load(string jsonlFilePath, bool resumeWriting = false)
    {
        ArgumentNullException.ThrowIfNull(jsonlFilePath);

        var entries = new List<GuardrailLedgerEntry>();
        using (var reader = new StreamReader(
            new FileStream(jsonlFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
        {
            var lineNumber = 0;
            while (reader.ReadLine() is { } line)
            {
                lineNumber++;
                if (!string.IsNullOrWhiteSpace(line))
                {
                    entries.Add(ParseEntry(line, jsonlFilePath, string.Create(CultureInfo.InvariantCulture, $"line {lineNumber}")));
                }
            }
        }

        // every entry is already in hand, so the file's tail is not read a second time
        var ledger = new HashChainLedger(resumeWriting ? jsonlFilePath : null, maxInMemoryEntries: null, continuePersistedChain: false);
        ledger._entries.AddRange(entries);

        // resuming has to continue the persisted numbering rather than restart it
        if (resumeWriting && entries.Count > 0)
        {
            ledger._trimmed = entries[0].Seq;
            ledger._lastTrimmedHash = entries[0].PreviousHash;
        }

        return ledger;
    }

    /// <summary>Serializes the entries held in memory to an indented JSON array.</summary>
    public string Export()
    {
        lock (_entriesLock)
        {
            return JsonSerializer.Serialize(_entries, JsonOptions);
        }
    }

    private static GuardrailLedgerEntry ParseEntry(string line, string path, string location)
    {
        try
        {
            if (JsonSerializer.Deserialize<GuardrailLedgerEntry>(line, JsonReadOptions) is { } entry)
                return entry;
        }
        catch (JsonException ex)
        {
            throw NotAnEntry(path, location, ex);
        }

        throw NotAnEntry(path, location, innerException: null);
    }

    private static InvalidDataException NotAnEntry(string path, string location, Exception? innerException) =>
        new($"Ledger file '{path}': {location} is not a valid ledger entry. " +
            "The file may end in an incomplete write or have been edited.", innerException);

    private static int ReadLastByte(FileStream file)
    {
        file.Position = file.Length - 1;
        return file.ReadByte();
    }

    // scans backwards from the end of the file in blocks, so only the last line is read however long
    // the chain is. Returns null for a file that holds no line with content.
    private static string? ReadLastLine(FileStream file, string path)
    {
        var buffer = new byte[4096];
        long lineEnd = -1;
        long lineStart = -1;

        for (var position = file.Length; position > 0 && lineStart < 0;)
        {
            var count = (int)Math.Min(buffer.Length, position);
            position -= count;
            file.Position = position;
            file.ReadExactly(buffer, 0, count);

            for (var i = count - 1; i >= 0 && lineStart < 0; i--)
            {
                if (lineEnd < 0)
                {
                    if (!IsBlank(buffer[i]))
                        lineEnd = position + i + 1;
                }
                else if (buffer[i] == '\n')
                {
                    lineStart = position + i + 1;
                }
            }

            if (lineStart < 0 && lineEnd >= 0 && lineEnd - position > MaxEntryBytes)
                throw NotAnEntry(path, "the last line", innerException: null);
        }

        if (lineEnd < 0)
            return null;

        lineStart = Math.Max(lineStart, 0);
        var bytes = new byte[lineEnd - lineStart];
        file.Position = lineStart;
        file.ReadExactly(bytes);

        // UTF-8 never encodes another character with a '\n' byte, so the split above is safe; a byte
        // order mark can only precede the first line
        return Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF');
    }

    private static bool IsBlank(byte value) => value is (byte)'\n' or (byte)'\r' or (byte)' ' or (byte)'\t';

    // entries read from a file hold null wherever the JSON did, which never matches
    private static bool HashMatches(GuardrailLedgerEntry entry) =>
        entry.Hash is not null
        && entry.PreviousHash is not null
        && entry.Decision?.RuleOutcomes is not null
        && StringsEqual(entry.Hash, ComputeHash(entry.Seq, entry.PreviousHash, entry.Decision));

    // hashes are not secrets, so an ordinal compare is sufficient (and allocation-free)
    private static bool StringsEqual(string a, string b) => string.Equals(a, b, StringComparison.Ordinal);

    private static string ComputeHash(long seq, string previousHash, GuardrailDecision d)
    {
        // canonical, unambiguous serialization: every field is length-prefixed so no
        // combination of field values can be rebalanced across delimiters to forge a
        // colliding payload (raw Input/Output are user-controlled free text)
        var sb = new StringBuilder();
        AppendField(sb, seq.ToString(CultureInfo.InvariantCulture));
        AppendField(sb, previousHash);
        AppendField(sb, d.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        AppendField(sb, d.PolicyName);
        AppendField(sb, d.Phase.ToString());
        AppendField(sb, d.AgentName);
        AppendField(sb, d.Outcome);
        AppendField(sb, d.BlockingRuleName);
        AppendField(sb, d.Severity.ToString());
        AppendField(sb, d.BlockReason);
        AppendField(sb, d.WasModified ? "1" : "0");
        AppendField(sb, d.InputHash);
        AppendField(sb, d.OutputHash);
        // bind the raw captured content (when present) into the chain so tampering with
        // Input/Output is detected, not just their hashes
        AppendField(sb, d.Input);
        AppendField(sb, d.Output);
        AppendField(sb, d.RuleOutcomes.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var ro in d.RuleOutcomes)
        {
            AppendField(sb, ro.RuleName);
            AppendField(sb, ro.Outcome);
        }

        // appended only when present, so decisions recorded without a stage hash as they always have;
        // the rule-outcome count above fixes where the outcomes end, so this can't be mistaken for one
        if (d.Stage is not null)
        {
            AppendField(sb, "stage");
            AppendField(sb, d.Stage);
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexStringLower(bytes);
    }

    // length-prefixes a field as "<charCount>:<value>|" so the field boundary is
    // unambiguous regardless of what characters the value contains
    private static void AppendField(StringBuilder sb, string? value)
    {
        value ??= string.Empty;
        sb.Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append('|');
    }

    /// <summary>Computes the SHA-256 (hex) of a text value, for input/output hashes.</summary>
    public static string HashText(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
