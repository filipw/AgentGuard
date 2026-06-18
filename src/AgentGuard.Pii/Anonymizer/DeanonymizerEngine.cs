using AgentGuard.Pii.Anonymizer.Operators;

namespace AgentGuard.Pii.Anonymizer;

/// <summary>
/// Reverses a prior anonymization: applies reverse operators (default <c>decrypt</c>; <c>custom</c>
/// supported) over the <see cref="OperatorResult"/> spans an <see cref="AnonymizerEngine"/> emitted,
/// restoring the original PII text. Operates end-to-start over the spans so earlier offsets stay valid.
/// </summary>
public sealed class DeanonymizerEngine
{
    private const string DefaultOperator = "decrypt";

    private readonly OperatorsFactory _operatorsFactory = new();

    /// <summary>The anonymize operators whose effect a built-in reverse operator can undo.</summary>
    private static readonly HashSet<string> _reversibleOperators = new(StringComparer.Ordinal)
    {
        "encrypt",
        "custom",
    };

    /// <summary>Registers or replaces a reverse operator on this engine.</summary>
    public void AddOperator(IOperator op) => _operatorsFactory.AddOperator(op);

    /// <summary>Returns the names of available reverse operators.</summary>
    public IReadOnlyCollection<string> GetDeanonymizers() => _operatorsFactory.GetDeanonymizers();

    /// <summary>
    /// Returns <c>true</c> if a span anonymized with <paramref name="anonymizeOperatorName"/> can be
    /// reversed (only <c>encrypt</c> and <c>custom</c> are reversible; <c>replace</c>/<c>redact</c>/
    /// <c>mask</c>/<c>hash</c>/<c>keep</c> are lossy).
    /// </summary>
    public static bool IsReversible(string anonymizeOperatorName) =>
        _reversibleOperators.Contains(anonymizeOperatorName);

    /// <summary>
    /// Restores the original text from <paramref name="anonymizedText"/> using the per-span
    /// <paramref name="items"/> produced by anonymization and the reverse <paramref name="operators"/>
    /// (keyed by entity type, with an optional <c>DEFAULT</c>). Reverse operators default to
    /// <c>decrypt</c>.
    /// </summary>
    /// <param name="anonymizedText">The full anonymized text.</param>
    /// <param name="items">The per-span operator results emitted by <see cref="AnonymizerEngine.Anonymize"/>.</param>
    /// <param name="operators">Reverse operator configs by entity type (e.g. <c>decrypt</c> with the key).</param>
    /// <exception cref="InvalidOperationException">Thrown when a span was anonymized with a non-reversible operator and a <c>decrypt</c> reverse is requested for it.</exception>
    public EngineResult Deanonymize(
        string anonymizedText,
        IReadOnlyList<OperatorResult> items,
        IReadOnlyDictionary<string, OperatorConfig> operators)
    {
        ArgumentNullException.ThrowIfNull(anonymizedText);
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(operators);

        var operatorMap = EnsureDefaultOperator(operators);

        var builder = new TextReplaceBuilder(anonymizedText);
        var result = new EngineResult();

        var sorted = items.OrderByDescending(i => i.Start).ThenByDescending(i => i.End).ToList();

        foreach (var item in sorted)
        {
            var textToOperateOn = builder.GetTextInPosition(item.Start, item.End);
            var config = GetOperatorConfig(item.EntityType, operatorMap);

            // a decrypt reverse only makes sense for an encrypted span; surface lossy operators clearly
            // instead of producing garbage. callers can still supply a custom reverse for other cases.
            if (config.OperatorName == DefaultOperator && !string.Equals(item.Operator, "encrypt", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Cannot reverse entity '{item.EntityType}': it was anonymized with the non-reversible " +
                    $"'{item.Operator}' operator. Only 'encrypt' spans can be decrypted; provide a custom " +
                    "reverse operator for this entity type if appropriate.");
            }

            var op = _operatorsFactory.Create(config.OperatorName, OperatorType.Deanonymize);
            var parameters = new Dictionary<string, object>(config.Parameters)
            {
                [OperatorParams.EntityType] = item.EntityType,
            };

            op.Validate(parameters);
            var changedText = op.Operate(textToOperateOn, parameters);

            var indexFromEnd = builder.ReplaceTextGetInsertionIndex(changedText, item.Start, item.End);
            result.AddItem(new OperatorResult(0, indexFromEnd, item.EntityType, changedText, op.Name));
        }

        result.SetText(builder.OutputText);
        result.NormalizeItemIndexes();
        return result;
    }

    private static OperatorConfig GetOperatorConfig(string entityType, IReadOnlyDictionary<string, OperatorConfig> operatorsMetadata) =>
        operatorsMetadata.TryGetValue(entityType, out var config) ? config : operatorsMetadata["DEFAULT"];

    private static IReadOnlyDictionary<string, OperatorConfig> EnsureDefaultOperator(IReadOnlyDictionary<string, OperatorConfig>? operators)
    {
        var defaultOperator = new OperatorConfig(DefaultOperator);
        if (operators is null || operators.Count == 0)
        {
            return new Dictionary<string, OperatorConfig> { ["DEFAULT"] = defaultOperator };
        }

        if (operators.ContainsKey("DEFAULT"))
        {
            return operators;
        }

        return new Dictionary<string, OperatorConfig>(operators) { ["DEFAULT"] = defaultOperator };
    }
}
