using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

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

    /// <summary>Sanitize the chunk (e.g. redact PII, strip injection attempts) but keep it.</summary>
    Sanitize
}

/// <summary>
/// Options for the retrieval guardrail rule.
/// </summary>
public sealed class RetrievalGuardrailOptions
{
    /// <summary>Check for prompt injection patterns embedded in retrieved content. Default: true.</summary>
    public bool DetectPromptInjection { get; init; } = true;

    /// <summary>Check for PII in retrieved chunks. Default: false.</summary>
    public bool DetectPII { get; init; }

    /// <summary>Check for secrets in retrieved chunks. Default: true.</summary>
    public bool DetectSecrets { get; init; } = true;

    /// <summary>Minimum relevance score threshold. Chunks below this are filtered. Default: null (no filtering).</summary>
    public double? MinRelevanceScore { get; init; }

    /// <summary>Maximum number of chunks to allow. Excess chunks (lowest score) are dropped. Default: null (no limit).</summary>
    public int? MaxChunks { get; init; }

    /// <summary>Action to take when a chunk violates a filter. Default: Remove.</summary>
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
/// This rule operates on the <see cref="GuardrailContext.Properties"/> bag — callers place
/// retrieved chunks under the <c>RetrievalChunks</c> key, and the rule writes back approved
/// chunks under <c>ApprovedChunks</c>.
///
/// Order 8 — runs early, before prompt injection detection (order 10), so that poisoned
/// chunks are removed before downstream rules evaluate the combined context.
/// </summary>
public sealed class RetrievalGuardrailRule : IGuardrailRule
{
    private readonly RetrievalGuardrailOptions _options;
    private readonly List<Regex> _injectionPatterns;

    // Well-known property keys for GuardrailContext.Properties
    public const string RetrievalChunksKey = "RetrievalChunks";
    public const string ApprovedChunksKey = "ApprovedChunks";
    public const string RetrievalResultKey = "RetrievalGuardrailResult";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    public RetrievalGuardrailRule(RetrievalGuardrailOptions? options = null)
    {
        _options = options ?? new();
        _injectionPatterns = BuildInjectionPatterns();
    }

    public string Name => "retrieval-guardrail";
    public GuardrailPhase Phase => GuardrailPhase.Input;
    public int Order => 8;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        // Retrieve chunks from the context properties bag
        if (!context.Properties.TryGetValue(RetrievalChunksKey, out var chunksObj) ||
            chunksObj is not IReadOnlyList<RetrievedChunk> chunks ||
            chunks.Count == 0)
        {
            // No chunks to evaluate — pass through
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var result = EvaluateChunks(chunks);

        // Store results back in the context properties
        context.Properties[ApprovedChunksKey] = result.ApprovedChunks;
        context.Properties[RetrievalResultKey] = result;

        if (result.FilteredCount > 0)
        {
            return ValueTask.FromResult(new GuardrailResult
            {
                IsModified = true,
                ModifiedText = context.Text,  // Original user query unchanged
                Reason = $"Retrieval guardrail filtered {result.FilteredCount} of {chunks.Count} chunks",
                Metadata = new Dictionary<string, object>
                {
                    ["filteredCount"] = result.FilteredCount,
                    ["totalChunks"] = chunks.Count,
                    ["approvedCount"] = result.ApprovedChunks.Count
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
            var (isViolation, reason, filter) = EvaluateChunkContent(chunk.Content);

            if (isViolation)
            {
                if (_options.Action == RetrievalFilterAction.Remove)
                {
                    evaluations.Add(new ChunkEvaluationResult
                    {
                        Chunk = chunk,
                        IsFiltered = true,
                        Reason = reason,
                        TriggeredFilter = filter
                    });
                }
                else // Sanitize
                {
                    var sanitized = SanitizeContent(chunk.Content, filter!);
                    evaluations.Add(new ChunkEvaluationResult
                    {
                        Chunk = chunk,
                        IsFiltered = false,
                        SanitizedContent = sanitized,
                        Reason = reason,
                        TriggeredFilter = filter
                    });
                    approved.Add(new RetrievedChunk
                    {
                        Content = sanitized,
                        Source = chunk.Source,
                        Score = chunk.Score,
                        Metadata = chunk.Metadata
                    });
                }
            }
            else
            {
                evaluations.Add(new ChunkEvaluationResult { Chunk = chunk });
                approved.Add(chunk);
            }
        }

        return new RetrievalGuardrailResult
        {
            ApprovedChunks = approved,
            EvaluationResults = evaluations
        };
    }

    private (bool IsViolation, string? Reason, string? Filter) EvaluateChunkContent(string content)
    {
        // Check for prompt injection patterns
        if (_options.DetectPromptInjection)
        {
            foreach (var pattern in _injectionPatterns)
            {
                if (pattern.IsMatch(content))
                    return (true, "Retrieved chunk contains prompt injection pattern", "prompt-injection");
            }
        }

        // Check for secrets
        if (_options.DetectSecrets)
        {
            if (ContainsSecretPatterns(content))
                return (true, "Retrieved chunk contains secret/credential", "secrets");
        }

        // Check for PII
        if (_options.DetectPII)
        {
            if (ContainsPiiPatterns(content))
                return (true, "Retrieved chunk contains PII", "pii");
        }

        // Custom filters
        foreach (var (name, predicate) in _options.CustomFilters)
        {
            if (predicate(content))
                return (true, $"Retrieved chunk flagged by custom filter: {name}", name);
        }

        return (false, null, null);
    }

    private string SanitizeContent(string content, string filter)
    {
        return filter switch
        {
            "prompt-injection" => SanitizeInjection(content),
            "secrets" => SanitizeSecrets(content),
            "pii" => SanitizePii(content),
            _ => _options.SanitizationReplacement
        };
    }

    private string SanitizeInjection(string content)
    {
        var result = content;
        foreach (var pattern in _injectionPatterns)
        {
            result = pattern.Replace(result, _options.SanitizationReplacement);
        }
        return result;
    }

    private static readonly Regex[] SecretPatterns =
    [
        new(@"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
        new(@"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,255}(?![A-Za-z0-9_])", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
        new(@"-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?(?:DSA\s+)?(?:OPENSSH\s+)?PRIVATE\s+KEY-----", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
        new(@"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*[""']?([A-Za-z0-9_\-./+=]{20,})[""']?", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
        new(@"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
    ];

    private static bool ContainsSecretPatterns(string text)
    {
        foreach (var pattern in SecretPatterns)
        {
            if (pattern.IsMatch(text)) return true;
        }
        return false;
    }

    private string SanitizeSecrets(string content)
    {
        var result = content;
        foreach (var pattern in SecretPatterns)
        {
            result = pattern.Replace(result, _options.SanitizationReplacement);
        }
        return result;
    }

    private static readonly Regex[] PiiPatterns =
    [
        new(@"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
        new(@"(?<!\d)(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
        new(@"(?<!\d)\d{3}[\s\-]?\d{2}[\s\-]?\d{4}(?!\d)", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200)),
    ];

    private static bool ContainsPiiPatterns(string text)
    {
        foreach (var pattern in PiiPatterns)
        {
            if (pattern.IsMatch(text)) return true;
        }
        return false;
    }

    private string SanitizePii(string content)
    {
        var result = content;
        foreach (var pattern in PiiPatterns)
        {
            result = pattern.Replace(result, _options.SanitizationReplacement);
        }
        return result;
    }

    private static List<Regex> BuildInjectionPatterns()
    {
        return
        [
            // Indirect injection: instructions hidden in retrieved content
            new(@"(?i)(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidelines|prompts)", RegexOptions.Compiled, RegexTimeout),
            new(@"(?i)(?:you\s+(?:are|must|should)\s+now|new\s+instructions?|system\s+(?:prompt|override))\s*:", RegexOptions.Compiled, RegexTimeout),
            new(@"(?i)(?:act|behave|respond)\s+as\s+(?:if\s+)?(?:you\s+are|a\s+)", RegexOptions.Compiled, RegexTimeout),

            // End sequence / role hijacking in documents
            new(@"<\|(?:system|user|assistant|im_start|im_end|eot_id|endoftext)\|>", RegexOptions.Compiled, RegexTimeout),
            new(@"(?i)\[(?:INST|/INST|SYSTEM|/SYSTEM)\]", RegexOptions.Compiled, RegexTimeout),
            new(@"(?i)<<\s*SYS\s*>>", RegexOptions.Compiled, RegexTimeout),

            // Hidden instructions in HTML/markdown comments
            new(@"<!--\s*(?:ignore|system|instructions?|prompt)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),

            // Data exfiltration via injected URLs
            new(@"(?i)(?:fetch|load|visit|navigate|request|open)\s+(?:this\s+)?(?:url|link|page)\s*:", RegexOptions.Compiled, RegexTimeout),
        ];
    }
}
