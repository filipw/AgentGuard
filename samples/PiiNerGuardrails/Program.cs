// AgentGuard - PII + NER Redaction Sample
// Demonstrates offline PII redaction augmented with multilingual named-entity recognition:
// PERSON / LOCATION / ORGANIZATION / DATE_TIME spans (that regex cannot catch) are detected by an
// ONNX GLiNER model and resolved against the regex/checksum entities in a single order-20 pass.
//
// The model is BYO-download (not bundled). Fetch it first:
//   ./eng/download-gliner-model.sh
// then point the sample at the files:
//   AGENTGUARD_GLINER_ONNX_MODEL_PATH=./models/gliner/model.onnx \
//   AGENTGUARD_GLINER_TOKENIZER_PATH=./models/gliner/spm.model \
//   AGENTGUARD_GLINER_CONFIG_PATH=./models/gliner/config.json \
//   dotnet run --project samples/PiiNerGuardrails

using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Onnx;
using AgentGuard.Pii;
using Microsoft.Extensions.Logging.Abstractions;

Console.WriteLine("AgentGuard - PII + NER Redaction Demo");
Console.WriteLine(new string('=', 64));

var modelPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH");
var tokenizerPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH");
var configPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH");

if (string.IsNullOrEmpty(modelPath) || string.IsNullOrEmpty(tokenizerPath) || string.IsNullOrEmpty(configPath))
{
    Console.WriteLine("\nModel not configured. Download it and set the paths:");
    Console.WriteLine("  ./eng/download-gliner-model.sh");
    Console.WriteLine("  AGENTGUARD_GLINER_ONNX_MODEL_PATH=./models/gliner/model.onnx \\");
    Console.WriteLine("  AGENTGUARD_GLINER_TOKENIZER_PATH=./models/gliner/spm.model \\");
    Console.WriteLine("  AGENTGUARD_GLINER_CONFIG_PATH=./models/gliner/config.json \\");
    Console.WriteLine("    dotnet run --project samples/PiiNerGuardrails");
    return 0;
}

// NER spans (PERSON/LOCATION/ORGANIZATION/DATE_TIME) merge with the always-on regex/checksum
// recognizers (email, phone, credit card, US pack, ...) in the same order-20 PiiRule. Enable the
// German country pack too, to show country recognizers and NER coexisting.
var pipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("pii-ner")
        .RedactPiiWithNer(
            modelPath,
            tokenizerPath,
            configPath,
            threshold: 0.5f,
            piiOptions: new PiiOptions { Countries = ["de"] })
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var samples = new (string Lang, string Text)[]
{
    ("en", "Contact Jane Doe at jane.doe@acme.com or call +1 415 555 0132 in Berlin at ACME Corp on March 3rd."),
    ("de", "Kontaktieren Sie Herrn Klaus Müller in München bei der Siemens AG am 5. Mai."),
    ("ru", "Иван Петров живёт в Москве и работает в компании Газпром."),
};

foreach (var (lang, text) in samples)
{
    var ctx = new GuardrailContext { Text = text, Phase = GuardrailPhase.Input };
    var result = await pipeline.RunAsync(ctx);

    Console.WriteLine($"\n[{lang}] in : {text}");
    Console.WriteLine($"[{lang}] out: {result.FinalText}");
}

Console.WriteLine($"\n{new string('=', 64)}");
Console.WriteLine("NER (PERSON/LOCATION/ORGANIZATION/DATE_TIME) is an optional offline ONNX add-on that");
Console.WriteLine("augments the regex PII recognizers in one pass. See eng/gliner-eval/RESULTS.md.");
return 0;
