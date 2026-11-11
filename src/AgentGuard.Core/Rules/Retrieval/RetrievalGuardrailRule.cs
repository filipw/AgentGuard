using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ToolResult;

namespace AgentGuard.Core.Rules.Retrieval;

/// <summary>
/// Represents a retrieved chunk from a knowledge base or document store.
/// </summary>
public sealed class RetrievedChunk
{
    /// <summary>The text content of the retrieved chunk.</summary>
    public required string Content { get; init; }

    /// <summary>Optional source identifier (e.g. document name, URL, chunk ID).</summary>
    public string? Source { get; init; }

    /// <summary>Optional relevance/similarity score from the retrieval system.</summary>
    public double? Score { get; init; }

    /// <summary>Optional metadata about the chunk.</summary>
    public IDictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Result of evaluating a single retrieved chunk.
/// </summary>
public sealed class ChunkEvaluationResult
{
    /// <summary>The original chunk that was evaluated.</summary>
    public required RetrievedChunk Chunk { get; init; }

    /// <summary>Whether the chunk should be filtered out.</summary>
    public bool IsFiltered { get; init; }

    /// <summary>The modified content if the chunk was sanitized (null if unchanged).</summary>
    public string? SanitizedContent { get; init; }

    /// <summary>Reason for filtering or modification.</summary>
    public string? Reason { get; init; }

    /// <summary>Which filter triggered the action.</summary>
    public string? TriggeredFilter { get; init; }
}

/// <summary>
/// Result of processing all retrieved chunks through the retrieval guardrail.
/// </summary>
public sealed class RetrievalGuardrailResult
{
    /// <summary>Chunks that passed all filters (possibly sanitized).</summary>
    public required IReadOnlyList<RetrievedChunk> ApprovedChunks { get; init; }

    /// <summary>Per-chunk evaluation results (includes filtered chunks).</summary>
    public required IReadOnlyList<ChunkEvaluationResult> EvaluationResults { get; init; }

    /// <summary>Number of chunks filtered out.</summary>
    public int FilteredCount => EvaluationResults.Count(r => r.IsFiltered);
}

/// <summary>
/// Action to take when a chunk violates a retrieval filter.
/// </summary>
public enum RetrievalFilterAction
{
    /// <summary>Remove the chunk entirely from the context.</summary>
    Remove,

    /// <summary>
    /// Sanitize the chunk but keep it: secrets and PII are replaced where they stand, and an
    /// injected instruction is removed together with the rest of its paragraph, since a match only
    /// marks where an instruction starts.
    /// </summary>
    Sanitize
}

/// <summary>
/// Options for the retrieval guardrail rule.
/// </summary>
public sealed class RetrievalGuardrailOptions
{
    /// <summary>Check for prompt injection patterns embedded in retrieved content. Default: true.</summary>
    /// <remarks>
    /// Retrieved content is checked the way tool results are: with the patterns of
    /// <see cref="ToolResultGuardrailRule"/> for <see cref="InjectionRiskLevel"/>, on the text as
    /// stored and with its invisible characters removed, and inside encoded runs. Invisible
    /// characters are also removed from the chunks handed on.
    /// </remarks>
    public bool DetectPromptInjection { get; init; } = true;

    /// <summary>
    /// How much of the indirect-injection pattern set to apply to retrieved content. Default:
    /// <see cref="ToolRiskLevel.Medium"/>. Use <see cref="ToolRiskLevel.High"/> for stores that hold
    /// content written by outsiders (inboxes, tickets, scraped pages), where wording that is only
    /// suspicious in a message should count too.
    /// </summary>
    public ToolRiskLevel InjectionRiskLevel { get; init; } = ToolRiskLevel.Medium;

    /// <summary>Check for PII in retrieved chunks. Default: false.</summary>
    public bool DetectPII { get; init; }

    /// <summary>Check for secrets in retrieved chunks. Default: true.</summary>
    public bool DetectSecrets { get; init; } = true;

    /// <summary>Minimum relevance score threshold. Chunks below this are filtered. Default: null (no filtering).</summary>
    public double? MinRelevanceScore { get; init; }

    /// <summary>Maximum number of chunks to allow. Excess chunks (lowest score) are dropped. Default: null (no limit).</summary>
    public int? MaxChunks { get; init; }

    /// <summary>Action to take when a chunk violates a filter. Default: Remove.</summary>
    /// <remarks>
    /// A chunk that could not be scanned within the pattern time budget is removed under either
    /// action: what was not checked cannot be sanitized.
    /// </remarks>
    public RetrievalFilterAction Action { get; init; } = RetrievalFilterAction.Remove;

    /// <summary>Custom chunk filters. Each receives the chunk text and returns true if the chunk should be flagged.</summary>
    public IList<(string Name, Func<string, bool> Predicate)> CustomFilters { get; init; } = [];

    /// <summary>Replacement text when sanitizing. Default: [FILTERED].</summary>
    public string SanitizationReplacement { get; init; } = "[FILTERED]";
}

/// <summary>
/// Guards RAG (Retrieval-Augmented Generation) pipelines by evaluating retrieved chunks
/// before they are injected into the LLM context. Prevents poisoned, inappropriate, or
/// low-quality knowledge base content from influencing agent responses.
///
/// This rule operates on the <see cref="GuardrailContext.Properties"/> bag - callers place
/// retrieved chunks under the <c>RetrievalChunks</c> key, and the rule writes back approved
/// chunks under <c>ApprovedChunks</c>. Nothing puts chunks there on its own: in a policy the rule
/// is inert until the code that retrieves does so, or calls <see cref="EvaluateChunks"/> directly.
///
/// Order 8 - runs early, before prompt injection detection (order 10), so that poisoned
/// chunks are removed before downstream rules evaluate the combined context.
/// </summary>
public sealed class RetrievalGuardrailRule : IGuardrailRule
{
    private readonly RetrievalGuardrailOptions _options;
    private readonly ToolResultGuardrailRule _injection;

    /// <summary>Property-bag key the caller places the retrieved chunks under.</summary>
    public const string RetrievalChunksKey = "RetrievalChunks";

    /// <summary>Property-bag key the rule writes the surviving chunks back to.</summary>
    public const string ApprovedChunksKey = "ApprovedChunks";

    /// <summary>Property-bag key carrying the full per-chunk evaluation.</summary>
    public const string RetrievalResultKey = "RetrievalGuardrailResult";

    private const string InjectionFilter = "prompt-injection";
    private const string SecretsFilter = "secrets";
    private const string PiiFilter = "pii";
    private const string IncompleteFilter = "scan-incomplete";

    // the name the injection check reports a chunk under
    private const string ChunkSourceName = "retrieval";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    // the (?i) patterns match case-insensitively; CultureInvariant keeps that independent of the
    // process culture (under tr-TR, "I" is not the upper case of "i")
    private const RegexOptions PatternOptions = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    /// <summary>Initializes a new instance of the <see cref="RetrievalGuardrailRule"/> class.</summary>
    /// <param name="options">Which filters to run, the action to take and any limits. Defaults when null.</param>
    public RetrievalGuardrailRule(RetrievalGuardrailOptions? options = null)
    {
        _options = options ?? new();

        // a retrieved chunk is content the model did not write and the user did not type, exactly
        // like a tool result, so it is held to the same patterns
        _injection = new ToolResultGuardrailRule(new ToolResultGuardrailOptions
        {
            Action = _options.Action == RetrievalFilterAction.Sanitize ? ToolResultAction.Sanitize : ToolResultAction.Block,
            SanitizationReplacement = _options.SanitizationReplacement
        });

        // compiled patterns generate IL on first use; pay it here, not on the first request
        RegexPatterns.Warm(SecretPatterns);
        RegexPatterns.Warm(PiiPatterns);
    }

    /// <inheritdoc />
    public string Name => "retrieval-guardrail";
    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;
    /// <inheritdoc />
    public int Order => 8;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        // Retrieve chunks from the context properties bag
        if (!context.Properties.TryGetValue(RetrievalChunksKey, out var chunksObj) ||
            chunksObj is not IEnumerable<RetrievedChunk> given)
        {
            // No chunks to evaluate - pass through
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var chunks = given as IReadOnlyList<RetrievedChunk> ?? given.ToList();
        if (chunks.Count == 0)
            return ValueTask.FromResult(GuardrailResult.Passed());

        var result = EvaluateChunks(chunks);

        // Store results back in the context properties
        context.Properties[ApprovedChunksKey] = result.ApprovedChunks;
        context.Properties[RetrievalResultKey] = result;

        var incomplete = result.EvaluationResults.Count(r => r.TriggeredFilter == IncompleteFilter);
        if (result.FilteredCount > 0)
        {
            return ValueTask.FromResult(new GuardrailResult
            {
                IsModified = true,
                // a chunk dropped because it could not be scanned is a failure to check, not a finding
                IsError = incomplete > 0,
                ModifiedText = context.Text,  // Original user query unchanged
                Reason = $"Retrieval guardrail filtered {result.FilteredCount} of {chunks.Count} chunks",
                Metadata = new Dictionary<string, object>
                {
                    ["filteredCount"] = result.FilteredCount,
                    ["totalChunks"] = chunks.Count,
                    ["approvedCount"] = result.ApprovedChunks.Count,
                    ["incompleteScans"] = incomplete
                }
            });
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <summary>
    /// Evaluates a list of retrieved chunks and returns the filtered/sanitized result.
    /// Can be called directly for standalone use outside the guardrail pipeline.
    /// </summary>
    public RetrievalGuardrailResult EvaluateChunks(IReadOnlyList<RetrievedChunk> chunks)
    {
        var workingChunks = chunks.ToList();

        // Apply relevance score filter first
        if (_options.MinRelevanceScore.HasValue)
        {
            workingChunks = workingChunks
                .Where(c => !c.Score.HasValue || c.Score.Value >= _options.MinRelevanceScore.Value)
                .ToList();
        }

        // Apply max chunks limit (keep highest scoring)
        if (_options.MaxChunks.HasValue && workingChunks.Count > _options.MaxChunks.Value)
        {
            workingChunks = workingChunks
                .OrderByDescending(c => c.Score ?? 0)
                .Take(_options.MaxChunks.Value)
                .ToList();
        }

        var evaluations = new List<ChunkEvaluationResult>();
        var approved = new List<RetrievedChunk>();

        // Track chunks removed by score/max filter
        foreach (var chunk in chunks)
        {
            if (!workingChunks.Contains(chunk))
            {
                evaluations.Add(new ChunkEvaluationResult
                {
                    Chunk = chunk,
                    IsFiltered = true,
                    Reason = chunk.Score.HasValue && _options.MinRelevanceScore.HasValue && chunk.Score.Value < _options.MinRelevanceScore.Value
                        ? $"Below minimum relevance score ({chunk.Score:F2} < {_options.MinRelevanceScore:F2})"
                        : "Exceeded maximum chunk limit",
                    TriggeredFilter = "relevance-filter"
                });
            }
        }

        // Evaluate remaining chunks for content violations
        foreach (var chunk in workingChunks)
        {
            var evaluation = EvaluateChunk(chunk);
            evaluations.Add(evaluation);

            if (evaluation.IsFiltered)
                continue;

            approved.Add(evaluation.SanitizedContent is null
                ? chunk
                : new RetrievedChunk
                {
                    Content = evaluation.SanitizedContent,
                    Source = chunk.Source,
                    Score = chunk.Score,
                    Metadata = chunk.Metadata
                });
        }

        return new RetrievalGuardrailResult
        {
            ApprovedChunks = approved,
            EvaluationResults = evaluations
        };
    }

    /// <summary>
    /// Runs every enabled filter over one chunk. All of them run, not just the first to fire, so a
    /// chunk carrying more than one kind of problem has each of them removed when sanitizing.
    /// </summary>
    private ChunkEvaluationResult EvaluateChunk(RetrievedChunk chunk)
    {
        var triggered = new List<(string Reason, string Filter)>();
        var sanitize = _options.Action == RetrievalFilterAction.Sanitize;
        var incomplete = false;

        // the text the later filters see and, when the chunk is kept, the text handed on
        var content = chunk.Content;

        if (_options.DetectPromptInjection && !string.IsNullOrWhiteSpace(content))
        {
            var inspection = _injection.Inspect(ChunkSourceName, content, _options.InjectionRiskLevel);
            incomplete |= inspection.TimedOut > 0;

            if (inspection.Violations.Count > 0)
            {
                triggered.Add(($"Retrieved chunk contains prompt injection pattern: {inspection.Violations[0].Description}", InjectionFilter));
            }

            // sanitized, or only cleared of the invisible characters used to break up keywords
            content = inspection.Cleaned ?? content;
        }

        if (_options.DetectSecrets && Find(SecretPatterns, content, ref incomplete))
        {
            triggered.Add(("Retrieved chunk contains secret/credential", SecretsFilter));
            if (sanitize)
                content = Replace(SecretPatterns, content);
        }

        if (_options.DetectPII && Find(PiiPatterns, content, ref incomplete))
        {
            triggered.Add(("Retrieved chunk contains PII", PiiFilter));
            if (sanitize)
                content = Replace(PiiPatterns, content);
        }

        foreach (var (name, predicate) in _options.CustomFilters)
        {
            if (predicate(content))
            {
                triggered.Add(($"Retrieved chunk flagged by custom filter: {name}", name));

                // a predicate says nothing about where the problem is, so nothing of the chunk is kept
                if (sanitize)
                    content = _options.SanitizationReplacement;
            }
        }

        // what was not scanned to the end can be neither passed nor sanitized
        if (incomplete)
        {
            return new ChunkEvaluationResult
            {
                Chunk = chunk,
                IsFiltered = true,
                Reason = $"Retrieved chunk could not be scanned within the {RegexTimeout.TotalMilliseconds:F0} ms pattern time budget",
                TriggeredFilter = IncompleteFilter
            };
        }

        var changed = !string.Equals(content, chunk.Content, StringComparison.Ordinal);
        if (triggered.Count == 0)
        {
            return changed
                ? new ChunkEvaluationResult
                {
                    Chunk = chunk,
                    SanitizedContent = content,
                    Reason = "Invisible characters removed from retrieved chunk"
                }
                : new ChunkEvaluationResult { Chunk = chunk };
        }

        return new ChunkEvaluationResult
        {
            Chunk = chunk,
            IsFiltered = !sanitize,
            SanitizedContent = sanitize ? content : null,
            Reason = string.Join("; ", triggered.Select(t => t.Reason)),
            TriggeredFilter = string.Join(", ", triggered.Select(t => t.Filter))
        };
    }

    private static bool Find(Regex[] patterns, string text, ref bool incomplete)
    {
        var found = false;
        foreach (var pattern in patterns)
        {
            try
            {
                found |= pattern.IsMatch(text);
            }
            catch (RegexMatchTimeoutException)
            {
                incomplete = true;
            }
        }

        return found;
    }

    private string Replace(Regex[] patterns, string text)
    {
        var result = text;
        foreach (var pattern in patterns)
        {
            try
            {
                // a MatchEvaluator, not the string overload: "$" sequences in the replacement are
                // not substitutions
                result = pattern.Replace(result, _ => _options.SanitizationReplacement);
            }
            catch (RegexMatchTimeoutException)
            {
                // where the match ends cannot be known, so nothing of the chunk is kept
                return _options.SanitizationReplacement;
            }
        }

        return result;
    }

    private static readonly Regex[] SecretPatterns =
    [
        // only a character an access key id could continue from rules a match out: "KEY=AKIA..." is
        // the usual way one is written down
        new(@"(?<![A-Za-z0-9/+])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])", PatternOptions, RegexTimeout),
        new(@"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,255}(?![A-Za-z0-9_])", PatternOptions, RegexTimeout),
        // the whole PEM block, so sanitizing removes the key body and not just its header line
        new(RegexPatterns.PemPrivateKeyBlock, PatternOptions, RegexTimeout),
        new(@"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*[""']?([A-Za-z0-9_\-./+=]{20,})[""']?", PatternOptions, RegexTimeout),
        // a token only starts where no base64url character precedes it, so a long run of them is scanned
        // once rather than once per "eyJ" inside it
        new(@"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", PatternOptions, RegexTimeout),
    ];

    private static readonly Regex[] PiiPatterns =
    [
        new(@"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", PatternOptions, RegexTimeout),
        new(@"(?<!\d)(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)", PatternOptions, RegexTimeout),
        new(@"(?<!\d)\d{3}[\s\-]?\d{2}[\s\-]?\d{4}(?!\d)", PatternOptions, RegexTimeout),
    ];
}
