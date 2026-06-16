namespace AgentGuard.Pii.Anonymizer;

/// <summary>
/// The output of an anonymize/deanonymize run: the transformed text and the list of operations
/// applied.
/// </summary>
public sealed class EngineResult
{
    private readonly List<OperatorResult> _items = [];

    /// <summary>Initializes a new instance of the <see cref="EngineResult"/> class.</summary>
    public EngineResult(string text = "")
    {
        Text = text;
    }

    /// <summary>The transformed text.</summary>
    public string Text { get; private set; }

    /// <summary>The operations applied, ordered from start to end after normalization.</summary>
    public IReadOnlyList<OperatorResult> Items => _items;

    /// <summary>Sets the transformed text.</summary>
    public void SetText(string text) => Text = text;

    /// <summary>Adds an operation result.</summary>
    public void AddItem(OperatorResult item) => _items.Add(item);

    /// <summary>
    /// Converts the intermediate end-relative indexes (produced while replacing from end to start)
    /// into absolute start/end offsets in the final text, ordered by start.
    /// </summary>
    public void NormalizeItemIndexes()
    {
        var textLen = Text.Length;
        foreach (var item in _items)
        {
            item.Start = textLen - item.End;
            item.End = item.Start + item.Text.Length;
        }

        _items.Sort((a, b) => a.Start.CompareTo(b.Start));
    }
}
