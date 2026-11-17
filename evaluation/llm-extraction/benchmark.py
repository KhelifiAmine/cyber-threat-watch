"""
Evaluate local LLMs (served by Ollama) on extracting structured fields from security advisories.

Each item is scored out of 6: 1 point for valid JSON, plus 1 point per field that is either
supported by the advisory text or left empty. A field whose content is not supported by the
text counts as a hallucination and scores 0.
"""

import argparse
import json
import re
import sys
import time
import urllib.request

FIELDS = ["affected_os", "affected_products", "impact_points", "remediation_steps", "temp_mitigation"]
STOPWORDS = {
    "the", "a", "an", "is", "in", "of", "to", "and", "or", "for", "with", "on", "at", "by", "as",
    "be", "was", "are", "has", "can", "that", "this", "it", "not", "from", "which", "may", "via", "its",
}
HALLUCINATION_THRESHOLD = 0.3  # minimum share of a value's keywords that must appear in the source
MAX_SCORE = 1 + len(FIELDS)

# Prompt v2 (the version used with the selected model)
PROMPT = (
    "You are a security data extractor. Read the advisory and fill the JSON below. "
    "Return ONLY the JSON object. No explanation, no markdown, no extra text. "
    "{\"affected_os\":[],\"affected_products\":[],"
    "\"impact_points\":[],\"remediation_steps\":[],\"temp_mitigation\":[]}"
    " STRICT RULES: "
    "1. Copy values word-for-word from the text only. "
    "2. Leave [] if the text does not explicitly state it - empty is correct. "
    "3. affected_os: only if an OS or platform is literally named in the text. "
    "4. remediation_steps: ONLY copy a sentence that explicitly says to apply a patch "
    "or update - do NOT add version numbers or steps not written verbatim in the text. "
    "5. If you are unsure whether something is in the text, leave the field []. "
    "6. Never use your training knowledge. The JSON must only reflect this text."
)


def load_samples(path):
    with open(path, encoding="utf-8") as f:
        samples = json.load(f)
    return [s for s in samples if len(str(s.get("description", ""))) > 100]


def ask(ollama_url, model, title, description, source, timeout, num_ctx):
    message = f"Title: {title}\nSource: {source}\nDescription: {description[:1500]}"
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": PROMPT}, {"role": "user", "content": message}],
        "stream": False,
        "options": {"temperature": 0.0, "num_ctx": num_ctx},
    }).encode()
    req = urllib.request.Request(f"{ollama_url}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())["message"]["content"].strip()
    except Exception as e:
        return f"ERROR: {e}"


def extract_json(raw):
    start, end = raw.find("{"), raw.rfind("}")
    return raw[start:end + 1] if start != -1 and end != -1 else raw


def keywords(text):
    words = re.findall(r"[a-zA-Z0-9]{3,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def unsupported_values(values, source_text):
    source_kw = keywords(source_text)
    bad = []
    for value in values:
        value_kw = keywords(str(value))
        if value_kw and len(value_kw & source_kw) / len(value_kw) < HALLUCINATION_THRESHOLD:
            bad.append(str(value)[:60])
    return bad


def score(raw, source_text):
    result = {"valid_json": False, "fields": {}, "hallucinations": [], "score": 0}
    try:
        parsed = json.loads(extract_json(raw))
    except Exception:
        return result
    result["valid_json"] = True
    points = 1
    for field in FIELDS:
        values = parsed.get(field, [])
        if not isinstance(values, list):
            values = [str(values)]
        if not values:
            result["fields"][field] = "empty"
            points += 1
            continue
        bad = unsupported_values(values, source_text)
        if bad:
            result["fields"][field] = "hallucinated"
            result["hallucinations"].append({"field": field, "values": bad})
        else:
            result["fields"][field] = "supported"
            points += 1
    result["score"] = points
    return result


def run(args, model, samples, label):
    print(f"\n{'=' * 70}\nMODEL: {model}  [{label}]\n{'=' * 70}")
    results, total_time = [], 0.0
    for i, s in enumerate(samples, 1):
        title, desc, source = str(s.get("title", ""))[:200], str(s["description"]), str(s.get("source", ""))
        print(f"[{i:02d}/{len(samples)}] {source} | {title[:50]}")
        t0 = time.time()
        raw = ask(args.ollama_url, model, title, desc, source, args.timeout, args.num_ctx)
        elapsed = time.time() - t0
        total_time += elapsed
        if raw.startswith("ERROR:"):
            print(f"  {raw}")
        res = score(raw, f"{title} {desc}")
        res["title"] = title
        results.append(res)
        print(f"  score={res['score']}/{MAX_SCORE}  hallucinations={len(res['hallucinations'])}  time={elapsed:.1f}s")
        for h in res["hallucinations"]:
            print(f"    !! {h['field']}: {h['values']}")

    n = len(results)
    summary = {
        "model": model,
        "set": label,
        "items": n,
        "valid_json": sum(r["valid_json"] for r in results),
        "accuracy": round(100 * sum(r["score"] for r in results) / (n * MAX_SCORE), 1),
        "hallucinated_fields": sum(len(r["hallucinations"]) for r in results),
        "avg_seconds": round(total_time / n, 1),
    }
    print(f"\n{'-' * 70}\n" + "\n".join(f"  {k}: {v}" for k, v in summary.items()) + f"\n{'-' * 70}")
    return summary, results


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--samples", help="JSON file of advisories (scored as a single set)")
    p.add_argument("--dev", help="development set JSON file")
    p.add_argument("--heldout", help="held-out set JSON file")
    p.add_argument("--models", nargs="+", default=["phi3.5"])
    p.add_argument("--ollama-url", default="http://localhost:11434")
    p.add_argument("--timeout", type=int, default=120)
    # Recent Ollama versions default to the model's full context window (128K for phi3.5),
    # which does not fit in 8 GB of GPU memory.
    p.add_argument("--num-ctx", type=int, default=4096)
    p.add_argument("--out", help="write per-item results to this JSON file")
    args = p.parse_args()

    sets = [(name, path) for name, path in
            [("samples", args.samples), ("development", args.dev), ("held-out", args.heldout)] if path]
    if not sets:
        p.error("give --samples, or --dev and/or --heldout")

    report = []
    for model in args.models:
        for label, path in sets:
            summary, results = run(args, model, load_samples(path), label)
            report.append({"summary": summary, "items": results})

    print("\nSUMMARY")
    for r in report:
        s = r["summary"]
        print(f"  {s['model']:<16} {s['set']:<12} accuracy={s['accuracy']}%  "
              f"hallucinated_fields={s['hallucinated_fields']}  valid_json={s['valid_json']}/{s['items']}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main())
