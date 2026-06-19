namespace AgentGuard.Pii.Anonymizer;

/// <summary>
/// Describes one applied operation in the anonymized output: the resulting span, the entity type and
/// the operator used.
/// </summary>
public sealed class OperatorResult
{
    /// <summary>Initializes a new instance of the <see cref="OperatorResult"/> class.</summary>
    public OperatorResult(int start, int end, string entityType, string text, string operatorName)
    {
        Start = start;
        End = end;
        EntityType = entityType;
        Text = text;
        Operator = operatorName;
    }

    /// <summary>Start offset of the operated span in the output text.</summary>
    public int Start { get; set; }

    /// <summary>End offset of the operated span in the output text.</summary>
    public int End { get; set; }

    /// <summary>The entity type that was operated on.</summary>
    public string EntityType { get; }

    /// <summary>The text that replaced the original span.</summary>
    public string Text { get; }

    /// <summary>The operator that produced the replacement.</summary>
    public string Operator { get; }
}
