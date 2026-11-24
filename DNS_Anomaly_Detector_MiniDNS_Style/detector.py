"""Core DNS traffic feature extraction and rule-based anomaly detection."""
from collections import Counter
from datetime import datetime
import csv

REQUIRED = {"timestamp", "domain", "query_type", "response"}

def load_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def preprocess(records):
    clean, errors = [], []
    for i, raw in enumerate(records, start=2):
        row = {str(k).strip().lower(): (v.strip() if isinstance(v, str) else v)
               for k, v in raw.items() if k is not None}
        missing = REQUIRED - set(row)
        if missing:
            errors.append(f"Row {i}: missing columns {', '.join(sorted(missing))}")
            continue
        try:
            datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            domain = row["domain"].lower().rstrip(".")
            if not domain or "." not in domain:
                raise ValueError("invalid domain")
            if not row["query_type"]:
                raise ValueError("missing query type")
            int(row["response"])
            row["domain"] = domain
            row["query_type"] = row["query_type"].upper()
            row["response"] = str(int(row["response"]))
            clean.append(row)
        except (ValueError, TypeError):
            errors.append(f"Row {i}: invalid timestamp, domain, query type or response")
    return clean, errors

def analyse(records, threshold=0.70):
    clean, errors = preprocess(records)
    if not clean:
        return {"records": [], "errors": errors, "summary": {
            "total_requests": 0, "unique_domains": 0, "repeated_requests": 0,
            "average_query_length": 0, "response_errors": 0,
            "pattern_score": 0, "threshold": threshold, "status": "NO DATA"
        }}
    counts = Counter(r["domain"] for r in clean)
    total = len(clean)
    repeated = sum(c - 1 for c in counts.values() if c > 1)
    avg_len = round(sum(len(r["domain"]) for r in clean) / total, 2)
    response_errors = sum(1 for r in clean if not r["response"].startswith("2"))
    # Transparent heuristic: repeated-query ratio + error ratio + concentration.
    repeated_ratio = repeated / total
    error_ratio = response_errors / total
    concentration = max(counts.values()) / total
    score = min(1.0, 0.60 * repeated_ratio + 0.25 * error_ratio + 0.15 * concentration)
    anomalous = score >= threshold
    flagged = []
    for domain, count in counts.items():
        if count > 1:
            flagged.append({"domain": domain, "requests": count,
                            "status": "REVIEW" if anomalous else "REPEATED"})
    summary = {
        "total_requests": total, "unique_domains": len(counts),
        "repeated_requests": repeated, "average_query_length": avg_len,
        "response_errors": response_errors, "pattern_score": round(score, 2),
        "threshold": threshold, "status": "ANOMALY DETECTED" if anomalous else "NORMAL"
    }
    return {"records": clean, "errors": errors, "summary": summary, "domain_counts": dict(counts),
            "flagged_domains": flagged}

def save_report(result, path="report.json"):
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
