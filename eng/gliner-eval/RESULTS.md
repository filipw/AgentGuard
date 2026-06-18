# GLiNER span NER - measured results (AgentGuard.Pii)

Model: [`urchade/gliner_multi_pii-v1`](https://huggingface.co/urchade/gliner_multi_pii-v1)
(mDeBERTa-v3-base, Apache-2.0), ONNX export (opset 19), default fp16. Re-run with
`python eval.py` on the next model bump.

## Threshold sweep (CoNLL-2003 validation, 200 sentences, exact char-span match)

Span counts as a TP only on an exact `(start, end, type)` match, so boundary-only disagreements
(e.g. "New York" vs "York") count as both FP and FN - this is a strict lower bound, especially for
ORG/LOC where GLiNER and CoNLL annotation boundaries differ.

| thresh | PERSON F1 | ORG F1 | LOC F1 | micro P | micro R | micro F1 |
|-------:|----------:|-------:|-------:|--------:|--------:|---------:|
| 0.30 | 0.913 | 0.448 | 0.532 | 0.662 | 0.626 | 0.643 |
| 0.40 | 0.917 | 0.449 | 0.525 | 0.678 | 0.615 | 0.645 |
| **0.50** | **0.921** | **0.469** | **0.504** | **0.705** | **0.601** | **0.649** |
| 0.60 | 0.920 | 0.460 | 0.450 | 0.710 | 0.568 | 0.631 |
| 0.70 | 0.934 | 0.470 | 0.417 | 0.739 | 0.549 | 0.630 |
| 0.80 | 0.941 | 0.456 | 0.371 | 0.789 | 0.511 | 0.620 |
| 0.90 | 0.928 | 0.451 | 0.256 | 0.820 | 0.459 | 0.588 |

**Default `NerThreshold` = 0.50** - the micro-F1 optimum and the model's standard operating point.
Above 0.5 precision keeps climbing but recall falls off (LOC sharply); below 0.5 micro-F1 is flat.
PERSON is strong across the range (F1 ~0.92); ORG/LOC are weaker, partly real and partly the
exact-span scoring penalty. Raise the threshold for a precision-leaning deployment, lower it to
favor recall. The analyzer's own `ScoreThreshold` (default 0.4) still applies on top.

## C# parity (`eng/gliner-csharp-eval`)

Assembly parity 4/5, decode parity 5/5 across en / de / ru / ar / zh (see `README.md`). Latin /
Cyrillic / Arabic reproduce the gliner library id-for-id and span-for-span; the lone miss is a CJK
fullwidth-punctuation tokenizer edge on text the whitespace splitter cannot segment (0 entities, so
decode is unaffected).

## fp16

~580 MB (vs ~1.16 GB fp32), max |delta P(span)| 0.0043 on multilingual probes. Default delivery.

## Scope

Detects PERSON / LOCATION / ORGANIZATION / DATE_TIME. DATE_TIME is not in CoNLL and is validated
qualitatively (fixtures + gated e2e: "March 3rd", "5. Mai" detected). Multilingual coverage is the
reason to add it (regex/spaCy NER are English-leaning); CJK is out of practical scope for the
whitespace word splitter. Position it as the offline span-NER lane of the order-20 PII pipeline,
complementing the regex/checksum recognizers, not replacing them.
