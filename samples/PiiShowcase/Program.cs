// AgentGuard - PII engine showcase (console)
// A narrated, end-to-end tour of the offline PII detection + de-identification engine:
//   1. detection breadth (generic + always-on US + opt-in country pack), scores, context boosting
//   2. anonymization operators (replace/redact/mask/hash/encrypt<->deanonymize/keep/custom)
//   3. structured JSON (path allow/deny) and CSV (column inference) redaction
//   4. batch over keyed records
//   5. allow-list + per-entity operator config
//   6. optional multilingual NER (PERSON/LOCATION/ORGANIZATION/DATE_TIME), gated on AGENTGUARD_GLINER_*
//
// Everything below the NER section is fully offline with no models - pure regex + checksums.

using System.Text;
using AgentGuard.Onnx;
using AgentGuard.Pii;
using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;
using AgentGuard.Pii.Batch;
using AgentGuard.Pii.Structured;

Console.OutputEncoding = Encoding.UTF8;

void Header(string title)
{
    Console.WriteLine();
    Console.WriteLine(new string('=', 72));
    Console.WriteLine($"  {title}");
    Console.WriteLine(new string('=', 72));
}

void BeforeAfter(string before, string after)
{
    Console.WriteLine($"  before : {before}");
    Console.WriteLine($"  after  : {after}");
}

Console.WriteLine("AgentGuard - PII engine showcase");
Console.WriteLine("Offline PII detection + de-identification, architecture inspired by Microsoft Presidio (MIT).");

// shared engines. enabling the German country pack alongside the always-on generic + US recognizers.
var registry = PiiRecognizers.CreateRegistry("en", ["de"]);
var analyzer = new AnalyzerEngine(registry, new LemmaContextAwareEnhancer(), defaultScoreThreshold: 0.4);
var anonymizer = new AnonymizerEngine();
var deanonymizer = new DeanonymizerEngine();

// ---------------------------------------------------------------------------
// 1. detection breadth + scores + context boosting
// ---------------------------------------------------------------------------
Header("1. Detection breadth (generic + US + German pack)");

const string breadthText =
    "Email jane.doe@acme.com, SSN 078-05-1120, card 4012888888881881, " +
    "IBAN DE89370400440532013000, VAT DE123456788, phone +1 415 555 0132.";

Console.WriteLine($"  text: {breadthText}\n");
var detections = analyzer.Analyze(breadthText, language: "en");
foreach (var d in detections.OrderBy(d => d.Start))
{
    var boosted = d.RecognitionMetadata?.ContainsKey(RecognizerResult.IsScoreEnhancedByContextKey) == true
        ? " (context-boosted)"
        : string.Empty;
    Console.WriteLine($"  {d.EntityType,-14} score={d.Score:F2}{boosted,-18} '{breadthText[d.Start..d.End]}'");
}

// ---------------------------------------------------------------------------
// 2. anonymization operators
// ---------------------------------------------------------------------------
Header("2. Operators (replace / redact / mask / hash / encrypt / keep / custom)");

const string opsText = "Reach John at john@acme.com or +1 415 555 0132; card 4012888888881881.";

const string encryptKey = "0123456789abcdef"; // 128-bit AES key

var operators = new Dictionary<string, OperatorConfig>
{
    ["EMAIL_ADDRESS"] = new("mask", new Dictionary<string, object>
    {
        [OperatorParams.MaskingChar] = "*",
        [OperatorParams.CharsToMask] = 6,
        [OperatorParams.FromEnd] = false,
    }),
    ["PHONE_NUMBER"] = new("hash", new Dictionary<string, object> { [OperatorParams.Salt] = "0123456789abcdef" }),
    ["CREDIT_CARD"] = new("redact"),
};

var opsResults = analyzer.Analyze(opsText, language: "en");
var anonymized = anonymizer.Anonymize(opsText, opsResults, operators);
BeforeAfter(opsText, anonymized.Text);

Console.WriteLine("\n  reversible round-trip (encrypt -> deanonymize):");
const string secretText = "Patient Mary booked at mary@clinic.org on file 078-05-1120.";
var encryptOps = new Dictionary<string, OperatorConfig>
{
    ["DEFAULT"] = new("encrypt", new Dictionary<string, object> { [OperatorParams.Key] = encryptKey }),
};
var secretResults = analyzer.Analyze(secretText, language: "en");
var encrypted = anonymizer.Anonymize(secretText, secretResults, encryptOps);
var deid = PiiDeidentificationResult.FromEngineResult(encrypted);

BeforeAfter(secretText, encrypted.Text);
Console.WriteLine($"  reversible? {deid.IsReversible}");

var restoreOps = new Dictionary<string, OperatorConfig>
{
    ["DEFAULT"] = new("decrypt", new Dictionary<string, object> { [OperatorParams.Key] = encryptKey }),
};
var restored = deanonymizer.Deanonymize(deid.AnonymizedText, deid.Items, restoreOps);
Console.WriteLine($"  restored : {restored.Text}");
Console.WriteLine($"  byte-for-byte match: {restored.Text == secretText}");

Console.WriteLine("\n  custom operator (keep last 4 of the card):");
var customOps = new Dictionary<string, OperatorConfig>
{
    ["CREDIT_CARD"] = new("custom", new Dictionary<string, object>
    {
        [CustomOperator.Lambda] = (Func<string, string>)(s =>
            s.Length <= 4 ? s : new string('#', s.Length - 4) + s[^4..]),
    }),
    ["DEFAULT"] = new("keep"), // leave everything else as-is
};
var customResult = anonymizer.Anonymize(opsText, analyzer.Analyze(opsText, language: "en"), customOps);
BeforeAfter(opsText, customResult.Text);

// ---------------------------------------------------------------------------
// 3. structured data: JSON (path scope) + CSV (column inference)
// ---------------------------------------------------------------------------
Header("3. Structured data (JSON path scope + CSV column inference)");

var structured = new StructuredEngine(analyzer);

const string json = """
    {
      "id": 4821,
      "user": { "name": "Acme Ltd", "email": "ada@acme.com", "phone": "+1 415 555 0132" },
      "active": true,
      "notes": "VIP since 2019"
    }
    """;

Console.WriteLine("  JSON - redact only $.user.email (allowlist):");
var jsonScoped = structured.AnonymizeJson(
    json,
    new JsonRedactionScope { IncludePaths = ["user.email"] },
    writeIndented: true);
Console.WriteLine(Indent(jsonScoped));

Console.WriteLine("\n  CSV - column inference redacts PII columns, leaves benign ones:");
var header = new[] { "name", "email", "card", "city" };
string[][] rawRows =
[
    ["Acme Ltd", "ada@acme.com", "4012888888881881", "Berlin"],
    ["Globex", "ed@globex.com", "4012888888881881", "Oslo"],
    ["Initech", "pp@initech.com", "4012888888881881", "Madrid"],
];
var rows = rawRows.Select(r => (IReadOnlyList<string>)r).ToList();
var csv = structured.AnonymizeCsv(header, rows);
Console.WriteLine($"  {string.Join(" | ", header)}");
foreach (var row in csv.Rows)
    Console.WriteLine($"  {string.Join(" | ", row)}");
Console.WriteLine($"  inferred PII columns: {string.Join(", ", csv.ColumnEntities.Select(kvp => $"{kvp.Key}={kvp.Value}"))}");

// ---------------------------------------------------------------------------
// 4. batch over keyed records
// ---------------------------------------------------------------------------
Header("4. Batch over keyed records");

var batchAnalyzer = new BatchAnalyzerEngine(analyzer);
var batchAnonymizer = new BatchAnonymizerEngine(anonymizer);

var records = new Dictionary<string, string>
{
    ["billing_email"] = "billing@acme.com",
    ["support_phone"] = "+1 415 555 0132",
    ["ticket_title"] = "Cannot log in",
};
var batchDetections = batchAnalyzer.Analyze(records);
var batchAnonymized = batchAnonymizer.Anonymize(records, batchDetections);
foreach (var (key, result) in batchAnonymized)
    BeforeAfter($"{key}: {records[key]}", $"{key}: {result.Text}");

// ---------------------------------------------------------------------------
// 5. allow-list + per-entity operator config
// ---------------------------------------------------------------------------
Header("5. Allow-list + per-entity operators");

const string allowText = "Contact support@acme.com or alerts@acme.com for help.";
Console.WriteLine("  allow-list exempts support@acme.com from redaction:");
var allowResults = analyzer.Analyze(
    allowText,
    language: "en",
    allowList: ["support@acme.com"]);
var allowAnon = anonymizer.Anonymize(allowText, allowResults, new Dictionary<string, OperatorConfig>
{
    ["EMAIL_ADDRESS"] = new("replace", new Dictionary<string, object> { [OperatorParams.NewValue] = "[email removed]" }),
});
BeforeAfter(allowText, allowAnon.Text);

// ---------------------------------------------------------------------------
// 6. optional multilingual NER (gated on AGENTGUARD_GLINER_* env vars)
// ---------------------------------------------------------------------------
Header("6. Multilingual NER (optional ONNX add-on)");

var nerModel = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH");
var nerTokenizer = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH");
var nerConfig = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH");

if (string.IsNullOrEmpty(nerModel) || string.IsNullOrEmpty(nerTokenizer) || string.IsNullOrEmpty(nerConfig))
{
    Console.WriteLine("  skipped - NER model not configured. To enable PERSON/LOCATION/ORGANIZATION/DATE_TIME:");
    Console.WriteLine("    ./eng/download-gliner-model.sh");
    Console.WriteLine("    AGENTGUARD_GLINER_ONNX_MODEL_PATH=./models/gliner/model.onnx \\");
    Console.WriteLine("    AGENTGUARD_GLINER_TOKENIZER_PATH=./models/gliner/spm.model \\");
    Console.WriteLine("    AGENTGUARD_GLINER_CONFIG_PATH=./models/gliner/config.json \\");
    Console.WriteLine("      dotnet run --project samples/PiiShowcase");
}
else
{
    // span entities (names, places, orgs, dates) merge with the regex/checksum recognizers in one pass
    var nerRegistry = PiiRecognizers.CreateRegistry("en", ["de"]);
    using var ner = new GlinerNerRecognizer(new GlinerNerOptions
    {
        ModelPath = nerModel,
        TokenizerPath = nerTokenizer,
        ConfigPath = nerConfig,
        NerThreshold = 0.5f,
    });
    nerRegistry.AddRecognizer(ner);
    var nerAnalyzer = new AnalyzerEngine(nerRegistry, new LemmaContextAwareEnhancer(), defaultScoreThreshold: 0.4);

    var nerSamples = new (string Lang, string Text)[]
    {
        ("en", "Jane Doe joined ACME Corp in Berlin on March 3rd; email jane.doe@acme.com."),
        ("de", "Klaus Müller arbeitet bei der Siemens AG in München seit dem 5. Mai."),
        ("ru", "Иван Петров живёт в Москве и работает в компании Газпром."),
    };

    foreach (var (lang, text) in nerSamples)
    {
        var results = nerAnalyzer.Analyze(text, language: "en");
        var redacted = anonymizer.Anonymize(text, results);
        Console.WriteLine($"\n  [{lang}]");
        BeforeAfter(text, redacted.Text);
    }
}

Console.WriteLine();
Console.WriteLine(new string('=', 72));
Console.WriteLine("  Done. All sections except NER run fully offline with no ML models.");
return 0;

static string Indent(string text) =>
    string.Join('\n', text.Split('\n').Select(line => "    " + line));
