# Local LLM evaluation for security advisory extraction

Comparison of small, locally hosted language models for extracting structured fields from
security advisories. This evaluation was carried out to choose the model used by Cyber Threat
Watch's enrichment step. This folder contains the evaluation method, the script and the recorded
results.

## Goal

Each collected advisory (CVE, CERT bulletin, vendor advisory) should be turned into five fields
used in client advisories:

| Field | Content |
|---|---|
| `affected_os` | Operating systems or platforms named in the advisory |
| `affected_products` | Products and versions named in the advisory |
| `impact_points` | Impacts described in the advisory |
| `remediation_steps` | Fixes stated in the advisory |
| `temp_mitigation` | Workarounds stated in the advisory |

## Constraints

- **Local only.** Advisory data could not be sent to an external API, so the model runs through
  [Ollama](https://ollama.com) on the same machine as the platform.
- **8 GB of GPU memory** (RTX 3070 Ti), shared with the rest of the pipeline. Target: models using
  about 5 GB or less.
- **No invented data.** The output is sent to clients, so a wrong product or version is worse than
  an empty field.

## Method

**Prompt.** The model receives the advisory text and must return only a JSON object with the five
fields. The rules require values to be copied from the text and fields to be left empty when the
text does not state the information (see `PROMPT` in [`benchmark.py`](benchmark.py)).

**Samples.** 30 advisories taken from the platform's database of public sources
(GitHub Security Advisories, TunCERT, CERT-FR and NVD):

- *Development set*: 15 items with the highest risk scores, used while adjusting the prompt.
- *Held-out set*: 15 items with the lowest risk scores, not looked at while adjusting the prompt.

Each set contains 3 items from each advisory source and 6 CVEs from NVD.

**Scoring.** Each item is scored out of 6:

- +1 if the output is valid JSON
- +1 per field if the field is either filled with content found in the text, or left empty
- 0 for a field whose content is not supported by the text (hallucination)

A value counts as a hallucination when fewer than 30% of its keywords appear in the advisory text.

Leaving a field empty is rewarded on purpose. In early runs the models assumed that every
advisory must list affected products and versions, and filled the field with plausible but
invented values. Rewarding a correct empty answer counters that bias. In the outputs I reviewed,
the models did not leave fields empty when the advisory did contain the information; the
problem was always over-filling, not omission.

**Pass criteria** (held-out set): at least 95% accuracy and zero hallucinated fields.

Smaller models were tested first, to avoid using more GPU memory than necessary.

## Results

| Model | Size | Dev. accuracy | Dev. hallucinations | Held-out accuracy | Held-out hallucinations | Avg. time / item | Result |
|---|---|---|---|---|---|---|---|
| qwen2.5:0.5b | 0.4 GB | 86.7% | 6 | 76.7% | 21 | 0.4 s | Fail |
| smollm2:1.7b | 1.0 GB | 60.0% | 18 | 58.9% | 13 | 0.7 s | Fail |
| qwen2.5:1.5b | 1.0 GB | 78.9% | 19 | 80.0% | 18 | 1.0 s | Fail |
| qwen2.5:3b | 1.9 GB | 90.0% | 9 | 94.4% | 5 | 1.3 s | Fail |
| qwen2.5:7b | 4.7 GB | 88.9% | 10 | 90.0% | 9 | 1.0 s | Fail |
| qwen2.5:0.5b, prompt v2 | 0.4 GB | 91.1% | 2 | 78.9% | 1 | 16.3 s | Fail |
| phi3.5, prompt v1 | 2.2 GB | 85.6% | 1 | 98.9% | 1 | 1.2 s | Fail |
| **phi3.5, prompt v2** | 2.2 GB | 81.1% | 5 | **100%** | **0** | 1.0 s | **Selected** |

Prompt v2 added an explicit rule against writing version numbers that do not appear word for word
in the text. Hallucination counts are numbers of fields across the 15 items of each set.

## Observations

- **Larger was not better.** qwen2.5:7b scored lower than qwen2.5:3b. The larger models more often
  filled gaps from their own knowledge, mostly with version numbers and fix steps that were not in
  the advisory.
- **Remediation was the hardest field.** Most hallucinations from qwen2.5:3b and 7b were in
  `remediation_steps`: plausible upgrade instructions that the advisory did not contain.
- **The smallest models failed differently.** qwen2.5:0.5b sometimes copied the prompt's own rules
  into the output, and with prompt v2 it timed out on long or French-language advisories.
  smollm2:1.7b produced invalid JSON on 5 held-out items.
- **phi3.5 was the most consistent** at following the "copy only, otherwise leave empty" rule.

## Decision and how it is used

phi3.5 with prompt v2 was selected: it met the pass criteria on the held-out set and fits easily in
the available GPU memory. It still produced 5 hallucinated fields and 2 invalid outputs on the
development set, which contains the longest and most complex advisories. In the platform:

- an invalid output falls back to empty fields;
- every extracted value is shown to an analyst, who must approve it before an advisory is sent.

The model assists the analyst; it does not publish anything on its own.

## Limitations

- **Small sample.** 15 items per set is enough to compare models for this decision, not to
  estimate accuracy precisely.
- **The two sets are not equally hard.** The held-out set contains lower-risk items, which tend to
  have shorter descriptions.
- **The hallucination check is a keyword heuristic.** It catches invented products and versions
  well, but it can miss a reworded value with the wrong meaning, or flag a correct paraphrase.
- **Not reproducible as published.** The samples came from the platform's database at the time
  of testing, which is not included. `benchmark.py` runs on any file of advisories in the format
  shown in [`samples.example.json`](samples.example.json).
- **Prompt versions differ between rounds.** Rounds 1 to 4 used the first prompt; prompt v2 was
  only applied to qwen2.5:0.5b and phi3.5.

## Running the benchmark

Requirements: Python 3.10+ and a running Ollama server with the models to test.

```bash
ollama pull phi3.5
python benchmark.py --samples samples.example.json --models phi3.5
```

Use `--dev` and `--heldout` instead of `--samples` to score two sets separately, and
`--ollama-url` if Ollama is not on `http://localhost:11434`. The context window is set to 4096
tokens (`--num-ctx`): recent Ollama versions otherwise load phi3.5 with its full 128K window,
which does not fit in 8 GB of GPU memory.
