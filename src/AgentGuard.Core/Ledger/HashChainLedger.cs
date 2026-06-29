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
    // the whole append. _entriesLock guards the list itself and is held only briefly so
    // readers are not blocked while a writer is busy hashing.
    private readonly object _appendLock = new();
    private readonly object _entriesLock = new();

    private readonly string? _jsonlPath;
    private readonly object _fileLock = new();

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

    /// <summary>
    /// Creates a ledger.
    /// </summary>
    /// <param name="jsonlFilePath">
    /// When provided, each appended entry is also written as one JSON object per line
    /// (JSONL) to this append-only file. The directory must already exist.
    /// </param>
    public HashChainLedger(string? jsonlFilePath = null)
    {
        _jsonlPath = jsonlFilePath;
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
        }

        if (_jsonlPath is not null)
        {
            lock (_fileLock)
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
            for (var i = 0; i < _entries.Count; i++)
            {
                var entry = _entries[i];

                var expectedPrevHash = i == 0 ? string.Empty : _entries[i - 1].Hash;
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
    }

    /// <summary>Serializes the entire ledger to an indented JSON array.</summary>
    public string Export()
    {
        lock (_entriesLock)
        {
            return JsonSerializer.Serialize(_entries, JsonOptions);
        }
    }

    private static bool StringsEqual(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string ComputeHash(long seq, string previousHash, GuardrailDecision d)
    {
        var sb = new StringBuilder();
        sb.Append(seq).Append('|');
        sb.Append(previousHash).Append('|');
        sb.Append(d.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)).Append('|');
        sb.Append(d.PolicyName).Append('|');
        sb.Append(d.Phase).Append('|');
        sb.Append(d.AgentName ?? string.Empty).Append('|');
        sb.Append(d.Outcome).Append('|');
        sb.Append(d.BlockingRuleName ?? string.Empty).Append('|');
        sb.Append(d.Severity).Append('|');
        sb.Append(d.BlockReason ?? string.Empty).Append('|');
        sb.Append(d.WasModified).Append('|');
        sb.Append(d.InputHash).Append('|');
        sb.Append(d.OutputHash).Append('|');
        foreach (var ro in d.RuleOutcomes)
        {
            sb.Append(ro.RuleName).Append('=').Append(ro.Outcome).Append(';');
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexStringLower(bytes);
    }

    /// <summary>Computes the SHA-256 (hex) of a text value, for input/output hashes.</summary>
    public static string HashText(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
