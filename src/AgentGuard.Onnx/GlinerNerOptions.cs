using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Onnx;

/// <summary>
/// Options for the offline ONNX named-entity recognizer (<see cref="GlinerNerRecognizer"/>) that adds
/// the span entity types regex cannot catch - <c>PERSON</c>, <c>LOCATION</c>, <c>ORGANIZATION</c>,
/// <c>DATE_TIME</c> - to the order-20 PII pipeline. The recognizer wraps a zero-shot span NER model
/// (mDeBERTa-v3 backbone, label-conditioned span scoring) and is multilingual.
/// <para>
/// The model must be downloaded separately - see <c>eng/download-gliner-model.sh</c>. Three files are
/// needed: the ONNX model, the mDeBERTa-v3 SentencePiece tokenizer (<c>spm.model</c>), and a small
/// <c>config.json</c> describing the special-token ids and maximum span width.
/// </para>
/// </summary>
public sealed class GlinerNerOptions
{
    /// <summary>
    /// Default GLiNER label -> AgentGuard entity-type map. The model-side prompt labels mirror the
    /// upstream spaCy NER output names; the values are the entity types <see cref="Pii"/> emits.
    /// </summary>
    public static IReadOnlyDictionary<string, string> DefaultEntityLabelMap { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["person"] = "PERSON",
            ["location"] = "LOCATION",
            ["organization"] = "ORGANIZATION",
            ["date"] = "DATE_TIME",
        };

    /// <summary>
    /// Path to the NER ONNX model file. The upstream GLiNER repo ships only PyTorch weights, so this is
    /// an ONNX export (see <c>eng/download-gliner-model.sh</c>). The download script defaults to fp16.
    /// </summary>
    public required string ModelPath { get; init; }

    /// <summary>
    /// Path to the mDeBERTa-v3-base SentencePiece model file (<c>spm.model</c>, the 250k multilingual
    /// vocab - the same tokenizer the Opir content-safety model uses).
    /// </summary>
    public required string TokenizerPath { get; init; }

    /// <summary>
    /// Path to the model <c>config.json</c>: special-token ids (<c>&lt;&lt;ENT&gt;&gt;</c>,
    /// <c>&lt;&lt;SEP&gt;&gt;</c>, CLS/SEP/PAD) and the maximum span width the export was traced with.
    /// </summary>
    public required string ConfigPath { get; init; }

    /// <summary>
    /// Probability threshold (0.0-1.0) a span must reach to be emitted. The decision is
    /// <c>emit iff sigmoid(span-label logit) &gt;= NerThreshold</c>. Default: <c>0.5</c>. This is the
    /// binding gate for NER spans and is independent of the analyzer's own <c>ScoreThreshold</c>, which
    /// still applies on top.
    /// </summary>
    public float NerThreshold { get; init; } = 0.5f;

    /// <summary>
    /// Maximum input token length. Text longer than this (after the label prompt) is chunked - see
    /// <see cref="MaxChunkChars"/>. Default: 384.
    /// </summary>
    public int MaxTokenLength { get; init; } = 384;

    /// <summary>
    /// Maximum span width in words. Candidate spans wider than this are not scored. Must match the
    /// value the ONNX graph was exported with. Default: 12.
    /// </summary>
    public int MaxSpanWidth { get; init; } = 12;

    /// <summary>
    /// Maximum number of characters processed per inference call. Longer input is split on sentence /
    /// whitespace boundaries and the results are offset-shifted back into the original text. Default: 1200.
    /// </summary>
    public int MaxChunkChars { get; init; } = 1200;

    /// <summary>
    /// Map of model-side prompt label (lowercase, e.g. <c>person</c>) to the AgentGuard entity type the
    /// span is reported as (e.g. <c>PERSON</c>). Defaults to <see cref="DefaultEntityLabelMap"/>. The
    /// set of prompt labels sent to the model is driven by which mapped entity types the engine requests.
    /// </summary>
    public IReadOnlyDictionary<string, string> EntityLabelMap { get; init; } = DefaultEntityLabelMap;
}
