using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Ledger;

/// <summary>
/// A tamper-evident, in-memory <see cref="IGuardrailLedger"/>. Every appended decision is
/// stamped into a SHA-256 hash chain: each entry hashes its own fields together with the
/// previous entry's hash, so any retroactive mutation breaks the chain and is detected by
/// <see cref="Verify()"/>. Optionally mirrors each entry to an append-only JSONL file.
/// Dependency-free (<see cref="System.Security.Cryptography"/> + <see cref="System.Text.Json"/>).
/// </summary>
/// <remarks>
/// Thread-safe. Appends are serialized (the chain is sequential) while reads
/// (<see cref="Entries"/>, <see cref="Count"/>, <see cref="Verify()"/>, <see cref="Export"/>)
/// take only a brief lock so they are not blocked while a writer computes its SHA-256 hash.
/// </remarks>
public sealed class HashChainLedger : IGuardrailLedger
{
    private readonly List<GuardrailLedgerEntry> _entries = [];

    // the hash chain is sequential, so appends must serialize; _appendLock is held for
    // the whole append (including the JSONL file write, so persisted order matches the
    // chain). _entriesLock guards the list itself and is held only briefly so readers
    // are not blocked while a writer is busy hashing.
    private readonly object _appendLock = new();
    private readonly object _entriesLock = new();

    private readonly string? _jsonlPath;

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
    /// </param>
    public HashChainLedger(string? jsonlFilePath = null)
    {
        _jsonlPath = jsonlFilePath;

        if (_jsonlPath is not null)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(_jsonlPath));
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }
    }

    /// <summary>The number of entries currently in the ledger.</summary>
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
                seq = _entries.Count;
                previousHash = seq == 0 ? string.Empty : _entries[(int)(seq - 1)].Hash;
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
            }

            // write the file inside the append lock so the JSONL line order always
            // matches the chain order (otherwise concurrent appends could interleave
            // file writes and make a later HashChainLedger.Load(...) verify as broken)
            if (_jsonlPath is not null)
            {
                File.AppendAllText(_jsonlPath,
                    JsonSerializer.Serialize(entry, JsonLineOptions) + Environment.NewLine);
            }
        }
    }

    /// <summary>A snapshot of all ledger entries in chain order.</summary>
    public IReadOnlyList<GuardrailLedgerEntry> Entries
    {
        get { lock (_entriesLock) { return _entries.ToArray(); } }
    }

    /// <summary>
    /// Recomputes the whole chain and verifies that every entry's hash and previous-hash
    /// linkage are intact.
    /// </summary>
    /// <returns><c>true</c> if the chain is intact; otherwise <c>false</c>.</returns>
    public bool Verify() => Verify(out _);

    /// <summary>
    /// Recomputes the whole chain and verifies its integrity, reporting the first broken
    /// entry when verification fails.
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
            return Verify(_entries, out brokenAtSeq);
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
    public static bool Verify(IReadOnlyList<GuardrailLedgerEntry> entries, out long brokenAtSeq)
    {
        ArgumentNullException.ThrowIfNull(entries);

        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];

            var expectedPrevHash = i == 0 ? string.Empty : entries[i - 1].Hash;
            if (!StringsEqual(entry.PreviousHash, expectedPrevHash))
            {
                brokenAtSeq = entry.Seq;
                return false;
            }

            var recomputed = ComputeHash(entry.Seq, entry.PreviousHash, entry.Decision);
            if (!StringsEqual(entry.Hash, recomputed))
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
    /// after a process restart.
    /// </summary>
    /// <param name="jsonlFilePath">Path to the JSONL file to load.</param>
    /// <param name="resumeWriting">
    /// When <c>true</c>, the returned ledger keeps writing to <paramref name="jsonlFilePath"/>,
    /// so appends extend the same persisted chain. When <c>false</c> (the default) the
    /// returned ledger is in-memory only (verification-only) and does not write back.
    /// </param>
    /// <returns>A ledger populated with the persisted entries.</returns>
    public static HashChainLedger Load(string jsonlFilePath, bool resumeWriting = false)
    {
        ArgumentNullException.ThrowIfNull(jsonlFilePath);

        var ledger = new HashChainLedger(resumeWriting ? jsonlFilePath : null);
        foreach (var line in File.ReadLines(jsonlFilePath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var entry = JsonSerializer.Deserialize<GuardrailLedgerEntry>(line, JsonReadOptions)
                ?? throw new InvalidDataException($"Failed to deserialize ledger entry: {line}");
            ledger._entries.Add(entry);
        }

        return ledger;
    }

    /// <summary>Serializes the entire ledger to an indented JSON array.</summary>
    public string Export()
    {
        lock (_entriesLock)
        {
            return JsonSerializer.Serialize(_entries, JsonOptions);
        }
    }

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

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexStringLower(bytes);
    }

    // length-prefixes a field as "<charCount>:<value>|" so the field boundary is
    // unambiguous regardless of what characters the value contains
    private static void AppendField(StringBuilder sb, string? value)
    {
        value ??= string.Empty;
        sb.Append(value.Length).Append(':').Append(value).Append('|');
    }

    /// <summary>Computes the SHA-256 (hex) of a text value, for input/output hashes.</summary>
    public static string HashText(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
