using AgentGuard.Core.Builders;
using AgentGuard.Pii;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Analyzer.Context;
using TasmanianDevil.Onnx;

namespace AgentGuard.Onnx;

/// <summary>
/// Extension methods for adding ONNX-based guardrail rules to the policy builder.
/// </summary>
public static class OnnxGuardrailBuilderExtensions
{
    /// <summary>
    /// Adds ONNX-based prompt injection detection using the bundled StackOne Defender multi-head
    /// model (minilm-multihead-v5, order 11). This is the recommended ONNX classifier - fast (~8 ms),
    /// calibrated, and requires no separate download. Runs before DeBERTa (order 12) and
    /// LLM-based detection (order 15).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">Optional configuration. If null, default options with bundled model are used.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithDefender(
        this GuardrailPolicyBuilder builder,
        DefenderPromptInjectionOptions? options = null)
    {
        builder.AddRule(new DefenderPromptInjectionRule(options));
        return builder;
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection using the bundled StackOne Defender multi-head
    /// model (minilm-multihead-v5, order 11) with a custom main-head threshold.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="mainThreshold">Main-head block threshold (0.0-1.0). Default in options: 0.75.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithDefender(
        this GuardrailPolicyBuilder builder,
        float mainThreshold)
    {
        return builder.BlockPromptInjectionWithDefender(new DefenderPromptInjectionOptions { MainThreshold = mainThreshold });
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using the DeBERTa v3 model.
    /// The ONNX model must be downloaded separately - see <c>eng/download-onnx-model.sh</c>.
    /// For most use cases, prefer <see cref="BlockPromptInjectionWithDefender(GuardrailPolicyBuilder, DefenderPromptInjectionOptions?)"/>
    /// which uses the bundled StackOne Defender model (faster, higher accuracy, no download required).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">ONNX model options including model and tokenizer file paths.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithDeberta(
        this GuardrailPolicyBuilder builder,
        OnnxPromptInjectionOptions options)
    {
        builder.AddRule(new OnnxPromptInjectionRule(options));
        return builder;
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using the DeBERTa v3 model.
    /// The ONNX model must be downloaded separately - see <c>eng/download-onnx-model.sh</c>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="modelPath">Path to the ONNX model file.</param>
    /// <param name="tokenizerPath">Path to the SentencePiece model file.</param>
    /// <param name="threshold">Confidence threshold (0.0-1.0). Default: 0.5.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithDeberta(
        this GuardrailPolicyBuilder builder,
        string modelPath,
        string tokenizerPath,
        float threshold = 0.5f)
    {
        return builder.BlockPromptInjectionWithDeberta(new OnnxPromptInjectionOptions
        {
            ModelPath = modelPath,
            TokenizerPath = tokenizerPath,
            Threshold = threshold
        });
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using the PIGuard DeBERTa v3 model
    /// (<c>leolee99/PIGuard</c>, ACL 2025, MIT). Trained with the "Mitigating Over-defense for Free"
    /// strategy: strong on indirect / code-style injection while keeping benign false positives low.
    /// The ONNX model must be downloaded separately - see <c>eng/download-piguard-model.sh</c>.
    /// Defaults to a 0.9 threshold (PIGuard's argmax over-blocks; 0.9 is the measured operating point).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">PIGuard model options including model and tokenizer file paths.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithPIGuard(
        this GuardrailPolicyBuilder builder,
        PIGuardPromptInjectionOptions options)
    {
        builder.AddRule(new PIGuardPromptInjectionRule(options));
        return builder;
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using the PIGuard DeBERTa v3 model.
    /// The ONNX model must be downloaded separately - see <c>eng/download-piguard-model.sh</c>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="modelPath">Path to the PIGuard ONNX model file.</param>
    /// <param name="tokenizerPath">Path to the DeBERTa v3 SentencePiece model file (<c>spm.model</c>).</param>
    /// <param name="threshold">Confidence threshold (0.0-1.0). Default: 0.9.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithPIGuard(
        this GuardrailPolicyBuilder builder,
        string modelPath,
        string tokenizerPath,
        float threshold = 0.9f)
    {
        return builder.BlockPromptInjectionWithPIGuard(new PIGuardPromptInjectionOptions
        {
            ModelPath = modelPath,
            TokenizerPath = tokenizerPath,
            Threshold = threshold
        });
    }

    /// <summary>
    /// Adds offline, multilingual content-safety detection (order 50) using the Opir-multilang model
    /// (<c>knowledgator/opir-multitask-multilang-v1.0</c>, GLiClass over mDeBERTa-v3-base, Apache-2.0).
    /// Scores text against a frozen harm taxonomy (toxicity, hate speech, violence, sexual content,
    /// self-harm, harassment) in any language and blocks when the strongest per-label probability
    /// reaches the threshold. Its niche is non-English content safety, where the bundled Defender
    /// classifier (English-only) and cloud APIs (per-call, PII-bound) leave a gap.
    /// The ONNX model must be downloaded separately - see <c>eng/download-opir-model.sh</c>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">Opir options including model, tokenizer, and prefix file paths.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockUnsafeContentWithOpir(
        this GuardrailPolicyBuilder builder,
        OpirSafetyOptions options)
    {
        builder.AddRule(new OpirSafetyRule(options));
        return builder;
    }

    /// <summary>
    /// Adds offline, multilingual content-safety detection (order 50) using the Opir-multilang model.
    /// The ONNX model must be downloaded separately - see <c>eng/download-opir-model.sh</c>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="modelPath">Path to the Opir-multilang ONNX model file.</param>
    /// <param name="tokenizerPath">Path to the mDeBERTa-v3 SentencePiece model file (<c>spm.model</c>).</param>
    /// <param name="prefixPath">Path to the frozen-taxonomy label-prefix file (<c>prefix.json</c>).</param>
    /// <param name="threshold">Block threshold (0.0-1.0) on the max per-label probability. Default: 0.5.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockUnsafeContentWithOpir(
        this GuardrailPolicyBuilder builder,
        string modelPath,
        string tokenizerPath,
        string prefixPath,
        float threshold = 0.5f)
    {
        return builder.BlockUnsafeContentWithOpir(new OpirSafetyOptions
        {
            ModelPath = modelPath,
            TokenizerPath = tokenizerPath,
            PrefixPath = prefixPath,
            Threshold = threshold
        });
    }

    /// <summary>
    /// Adds offline, multilingual PII redaction (order 20) that augments the regex/checksum
    /// recognizers with ONNX named-entity recognition, detecting the span entity types regex cannot
    /// catch - <c>PERSON</c>, <c>LOCATION</c>, <c>ORGANIZATION</c>, <c>DATE_TIME</c> - and resolving
    /// them against the regex entities in a single <c>PiiRule</c> pass. Opt-in and BYO-download (the
    /// NER model is not bundled - see <c>eng/download-gliner-model.sh</c>); not part of
    /// <see cref="UseDefaults"/>.
    /// <para>
    /// The NER spans flow through the same analyzer as the regex entities, so overlap resolution and
    /// anonymization treat them uniformly. <see cref="GlinerNerOptions.NerThreshold"/> (default 0.5) is
    /// the binding gate for NER spans; the analyzer's <see cref="PiiOptions.ScoreThreshold"/> still
    /// applies on top.
    /// </para>
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="nerOptions">NER model paths, threshold, span width, and label map.</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration (entities, countries, operators).</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithNer(
        this GuardrailPolicyBuilder builder,
        GlinerNerOptions nerOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(nerOptions);

        var language = piiOptions?.Language ?? "en";
        var registry = PiiRecognizers.CreateRegistry(language, piiOptions?.Countries);
        registry.AddRecognizer(new GlinerNerRecognizer(nerOptions, supportedLanguage: language));

        // defaultScoreThreshold 0 here; PiiRule applies PiiOptions.ScoreThreshold per evaluation.
        var engine = new AnalyzerEngine(
            registry,
            new LemmaContextAwareEnhancer(contextMatchingMode: piiOptions?.ContextMatchingMode ?? ContextMatchingMode.Substring),
            defaultScoreThreshold: 0);

        builder.AddRule(new PiiRule(piiOptions, analyzer: engine));
        return builder;
    }

    /// <summary>
    /// Adds offline, multilingual PII redaction (order 20) augmented with ONNX named-entity
    /// recognition (PERSON/LOCATION/ORGANIZATION/DATE_TIME). The NER model must be downloaded
    /// separately - see <c>eng/download-gliner-model.sh</c>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="modelPath">Path to the NER ONNX model file.</param>
    /// <param name="tokenizerPath">Path to the mDeBERTa-v3 SentencePiece model file (<c>spm.model</c>).</param>
    /// <param name="configPath">Path to the model <c>config.json</c> (special-token ids + max span width).</param>
    /// <param name="threshold">Span emission threshold (0.0-1.0). Default: 0.5.</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithNer(
        this GuardrailPolicyBuilder builder,
        string modelPath,
        string tokenizerPath,
        string configPath,
        float threshold = 0.5f,
        PiiOptions? piiOptions = null)
    {
        return builder.RedactPiiWithNer(
            new GlinerNerOptions
            {
                ModelPath = modelPath,
                TokenizerPath = tokenizerPath,
                ConfigPath = configPath,
                NerThreshold = threshold,
            },
            piiOptions);
    }

    /// <summary>
    /// Configures a sensible set of default guardrail rules including:
    /// input normalization (order 5), regex-based prompt injection (order 10),
    /// Defender ML-based prompt injection (order 11), PII redaction (order 20),
    /// secrets detection (order 22), tool call guardrails (order 45),
    /// and tool result guardrails (order 47).
    /// This provides a solid baseline that works fully offline with no additional configuration.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder UseDefaults(this GuardrailPolicyBuilder builder)
    {
        return builder
            .NormalizeInput()
            .BlockPromptInjection()
            .BlockPromptInjectionWithDefender()
            .RedactPii()
            .DetectSecrets()
            .GuardToolCalls()
            .GuardToolResults();
    }
}
