using System.Text.RegularExpressions;
using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Anonymizer.Operators;

namespace AgentGuard.Pii.Anonymizer;

/// <summary>
/// Applies anonymization operators to detected PII spans, resolving overlaps first.
/// </summary>
public sealed partial class AnonymizerEngine
{
    private const string DefaultOperator = "replace";

    private readonly OperatorsFactory _operatorsFactory = new();

    /// <summary>Registers or replaces an operator on this engine.</summary>
    public void AddOperator(IOperator op) => _operatorsFactory.AddOperator(op);

    /// <summary>Returns the names of available anonymize operators.</summary>
    public IReadOnlyCollection<string> GetAnonymizers() => _operatorsFactory.GetAnonymizers();

    /// <summary>Anonymizes <paramref name="text"/> using the detected <paramref name="analyzerResults"/>.</summary>
    public EngineResult Anonymize(
        string text,
        IReadOnlyList<RecognizerResult> analyzerResults,
        IReadOnlyDictionary<string, OperatorConfig>? operators = null,
        ConflictResolutionStrategy conflictResolution = ConflictResolutionStrategy.MergeSimilarOrContained,
        bool mergeEntitiesWithSpaces = true)
    {
        // work on copies so the caller's results are not mutated
        var results = analyzerResults
            .Select(r => new RecognizerResult(r.EntityType, r.Start, r.End, r.Score))
            .OrderBy(r => r.Start).ThenBy(r => r.End)
            .ToList();

        results = RemoveConflicts(results, conflictResolution);

        var merged = mergeEntitiesWithSpaces ? MergeEntitiesWithSpacesBetween(text, results) : results;

        var operatorMap = EnsureDefaultOperator(operators);

        return Operate(text, merged, operatorMap, OperatorType.Anonymize);
    }

    private static List<RecognizerResult> RemoveConflicts(
        List<RecognizerResult> analyzerResults,
        ConflictResolutionStrategy conflictResolution)
    {
        // step 1: merge intersecting results of the same entity type
        var tmp = new List<RecognizerResult>();
        var otherElements = new List<RecognizerResult>(analyzerResults);
        foreach (var result in analyzerResults)
        {
            otherElements.Remove(result);

            var merged = false;
            foreach (var other in otherElements)
            {
                if (other.EntityType != result.EntityType || result.Intersects(other) == 0)
                {
                    continue;
                }

                other.Start = Math.Min(result.Start, other.Start);
                other.End = Math.Max(result.End, other.End);
                other.Score = Math.Max(result.Score, other.Score);
                merged = true;
                break;
            }

            if (!merged)
            {
                otherElements.Add(result);
                tmp.Add(result);
            }
        }

        // step 2: drop results that conflict with (are contained in / dominated by) others
        var unique = new List<RecognizerResult>();
        otherElements = new List<RecognizerResult>(tmp);
        foreach (var result in tmp)
        {
            otherElements.Remove(result);
            if (!otherElements.Any(other => result.HasConflict(other)))
            {
                otherElements.Add(result);
                unique.Add(result);
            }
        }

        // step 3 (optional): trim partial overlaps so no spans intersect
        if (conflictResolution == ConflictResolutionStrategy.RemoveIntersections)
        {
            unique.Sort((a, b) => a.Start.CompareTo(b.Start));
            var index = 0;
            while (index < unique.Count - 1)
            {
                var current = unique[index];
                var next = unique[index + 1];
                if (current.End <= next.Start)
                {
                    index++;
                }
                else
                {
                    if (current.Score >= next.Score)
                    {
                        next.Start = current.End;
                    }
                    else
                    {
                        current.End = next.Start;
                    }

                    unique.Sort((a, b) => a.Start.CompareTo(b.Start));
                }
            }

            unique = unique.Where(e => e.Start <= e.End).ToList();
        }

        return unique;
    }

    private static List<RecognizerResult> MergeEntitiesWithSpacesBetween(string text, List<RecognizerResult> analyzerResults)
    {
        var merged = new List<RecognizerResult>();
        RecognizerResult? prev = null;
        foreach (var result in analyzerResults)
        {
            if (prev is not null &&
                prev.EntityType == result.EntityType &&
                WhitespaceRegex().IsMatch(text[prev.End..result.Start]))
            {
                merged.Remove(prev);
                result.Start = prev.Start;
            }

            merged.Add(result);
            prev = result;
        }

        return merged;
    }

    private EngineResult Operate(
        string text,
        IReadOnlyList<RecognizerResult> entities,
        IReadOnlyDictionary<string, OperatorConfig> operatorsMetadata,
        OperatorType operatorType)
    {
        var builder = new TextReplaceBuilder(text);
        var result = new EngineResult();

        var sorted = entities.OrderByDescending(e => e.Start).ThenByDescending(e => e.End).ToList();

        foreach (var entity in sorted)
        {
            var textToOperateOn = builder.GetTextInPosition(entity.Start, entity.End);
            var config = GetOperatorConfig(entity.EntityType, operatorsMetadata);

            var op = _operatorsFactory.Create(config.OperatorName, operatorType);
            var parameters = new Dictionary<string, object>(config.Parameters)
            {
                [OperatorParams.EntityType] = entity.EntityType,
            };

            op.Validate(parameters);
            var changedText = op.Operate(textToOperateOn, parameters);

            var indexFromEnd = builder.ReplaceTextGetInsertionIndex(changedText, entity.Start, entity.End);
            result.AddItem(new OperatorResult(0, indexFromEnd, entity.EntityType, changedText, op.Name));
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

        var copy = new Dictionary<string, OperatorConfig>(operators) { ["DEFAULT"] = defaultOperator };
        return copy;
    }

    [GeneratedRegex(@"^( )+$")]
    private static partial Regex WhitespaceRegex();
}
