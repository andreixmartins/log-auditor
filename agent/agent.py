
import os
import sys
import json
import re
import fnmatch
import pandas as pd
from tabulate import tabulate
import yaml

# -------------------------------
# Severity ordering for policy CI
# -------------------------------
SEVERITY_ORDER = {"info": 0, "warn": 1, "error": 2}

# -------------------------------
# Heuristic rule-based checks
# -------------------------------

def classify_row(row):
    """
    Heuristics; returns (category, reason) or (None, "uncertain").
    Categories: bad_logs, bad_format_logs, unnecessary_logs, ok
    """
    if bool(row.get("is_system_out_err")):
        return ("bad_logs", "Uses System.out/err")

    if bool(row.get("heuristic_pii_risk")):
        return ("bad_logs", "Possible PII in log message")

    if bool(row.get("uses_concat")):
        return ("bad_format_logs", "String concatenation in log call")

    if bool(row.get("placeholder_mismatch")):
        return ("bad_format_logs", "Placeholder/arg mismatch")

    if bool(row.get("heuristic_unnecessary")):
        return ("unnecessary_logs", "Low-signal message (entering/exiting/test/etc.)")

    return (None, "uncertain")


# ------------------------------------------------------
# Version-agnostic OpenAI client call (works on v1.x/0.x)
# ------------------------------------------------------

def call_openai(prompt: str, model: str) -> str:
    """
    Supports:
      - v1.x class client: responses or chat.completions
      - legacy 0.x module-level ChatCompletion
    Returns plain text; raises on error.
    """
    try:
        from openai import OpenAI  # v1.x
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        # Newer v1.x: responses API
        if hasattr(client, "responses"):
            r = client.responses.create(
                model=model,
                input=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            text = getattr(r, "output_text", None)
            if text:
                return text.strip()
            if getattr(r, "output", None):
                parts = []
                for item in r.output:
                    content = getattr(item, "content", None)
                    if not content:
                        continue
                    for c in content:
                        if getattr(c, "type", "") == "output_text":
                            parts.append(getattr(c, "text", ""))
                if parts:
                    return "".join(parts).strip()
            return str(r)

        # Older v1.x: chat.completions API
        if hasattr(client, "chat") and hasattr(client.chat, "completions"):
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            return r.choices[0].message.content.strip()

    except Exception:
        # Fall through to 0.x legacy
        pass

    # 0.x module-level API
    import openai as openai_legacy  # type: ignore
    openai_legacy.api_key = os.getenv("OPENAI_API_KEY")
    r = openai_legacy.ChatCompletion.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
    )
    return r["choices"][0]["message"]["content"].strip()


def llm_judge(message, level, code_context):
    """
    Uses LLM to decide between UNNECESSARY, BAD_FORMAT, or OK.
    Returns (category, reason) or (None, "...") if disabled/error.
    """
    if not os.getenv("OPENAI_API_KEY"):
        return None, "OpenAI disabled (no API key)"

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    prompt = f"""
You are auditing Java log statements. Decide if this log is UNNECESSARY, BAD_FORMAT, or OK.
- UNNECESSARY: low-signal noise (e.g., "entering method"), redundant or trivial logs.
- BAD_FORMAT: string concatenation or placeholder/arg issues.
Return exactly one of: UNNECESSARY, BAD_FORMAT, OK. Add a short reason.

LEVEL={level}
MESSAGE={message}
CODE_CONTEXT:
{code_context}
""".strip()

    try:
        text = call_openai(prompt, model)
        up = text.upper()
        if "UNNECESSARY" in up:
            return "unnecessary_logs", "LLM: " + text
        if "BAD_FORMAT" in up:
            return "bad_format_logs", "LLM: " + text
        return "ok", "LLM: " + text
    except Exception as e:
        return None, f"LLM error: {e}"


# ----------------
# Policy utilities
# ----------------

def _compile_regex_list(exprs, lists):
    compiled = []
    for e in exprs or []:
        if isinstance(e, str) and e.startswith("@"):
            key = e[1:]
            for sub in lists.get(key, []):
                compiled.append(re.compile(sub))
        else:
            compiled.append(re.compile(e))
    return compiled

def _path_is_excluded(path, globs):
    return any(fnmatch.fnmatch(path, g) for g in (globs or []))

def load_policy(path="log_policy.yaml"):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    policy = {
        "version": raw.get("version", 1),
        "default_category": raw.get("default_category", "ok"),
        "default_severity": raw.get("default_severity", "info"),
        "fail_on_severity": raw.get("fail_on_severity", "error"),
        "globals": raw.get("globals", {}),
        "rules": raw.get("rules", []),
        "lists": raw.get("lists", {}),
        "suppress": raw.get("suppress", []),
    }

    # Precompile regex for each rule
    for r in policy["rules"]:
        when = r.get("when", {})
        msg_re = when.get("message_regex_any_of", [])
        r["_message_regex"] = _compile_regex_list(msg_re, policy["lists"])

    # Suppression index
    suppress_ix = {}
    for s in policy["suppress"]:
        rid = s.get("id")
        if rid:
            suppress_ix.setdefault(rid, []).extend(s.get("paths", []))
    policy["_suppress_ix"] = suppress_ix

    return policy

def has_throwable_last_arg(row):
    """
    Heuristic: if there is at least 1 arg and placeholders roughly match,
    assume final arg could be Throwable. You can have the scanner emit a
    dedicated boolean for accuracy.
    """
    return bool(row.get("args_count", 0) >= 1 and not row.get("placeholder_mismatch", False))

def eval_policy_row(row, policy):
    """Return (matched, rule_id, category, severity, description, suggest) or (False, ...)."""
    file = row.get("file", "")

    if _path_is_excluded(file, policy.get("globals", {}).get("exclude_paths", [])):
        return (False, None, None, None, None, None)

    for r in policy["rules"]:
        w = r.get("when", {})

        # Booleans
        if "is_system_out_err" in w and bool(row.get("is_system_out_err")) != bool(w["is_system_out_err"]):
            continue
        if "uses_concat" in w and bool(row.get("uses_concat")) != bool(w["uses_concat"]):
            continue
        if "placeholder_mismatch" in w and bool(row.get("placeholder_mismatch")) != bool(w["placeholder_mismatch"]):
            continue
        if "has_throwable_last_arg" in w:
            if bool(has_throwable_last_arg(row)) != bool(w["has_throwable_last_arg"]):
                continue

        # Numerics
        if "message_bytes_gt" in w and not (int(row.get("message_bytes", 0)) > int(w["message_bytes_gt"])):
            continue

        # Level set
        if "level_in" in w:
            if str(row.get("level", "")).upper() not in set(map(str.upper, w["level_in"])):
                continue

        # Message regex any-of
        ok_re = True
        if r["_message_regex"]:
            text = str(row.get("message_template", ""))
            ok_re = any(rx.search(text) for rx in r["_message_regex"])
        if not ok_re:
            continue

        # Suppression by path
        for g in policy.get("_suppress_ix", {}).get(r.get("id"), []):
            if fnmatch.fnmatch(file, g):
                return (False, None, None, None, None, None)

        return (
            True,
            r.get("id"),
            r.get("category", policy["default_category"]),
            r.get("severity", policy["default_severity"]),
            r.get("description", ""),
            r.get("suggest", "")
        )

    return (False, None, None, None, None, None)


# -----------
# Main driver
# -----------

def main():
    if len(sys.argv) < 2:
        print("Usage: python agent.py logs.jsonl", file=sys.stderr)
        sys.exit(2)

    src = sys.argv[1]
    if not os.path.exists(src):
        print(f"Input file not found: {src}", file=sys.stderr)
        sys.exit(2)

    # Load extracted logs (from the Java scanner)
    rows = []
    with open(src, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                # tolerate partial / noisy lines
                continue

    if not rows:
        print("No data found in logs.jsonl")
        return

    df = pd.DataFrame(rows)

    # Ensure required columns exist with safe defaults
    required_defaults = {
        "file": "",
        "line": -1,
        "kind": "",
        "level": "",
        "message_template": "",
        "message_bytes": 0,
        "args_count": 0,
        "placeholder_count": 0,
        "placeholder_mismatch": False,
        "uses_concat": False,
        "is_system_out_err": False,
        "heuristic_unnecessary": False,
        "heuristic_pii_risk": False,
    }
    for col, default in required_defaults.items():
        if col not in df.columns:
            df[col] = default

    # Load policy (if present)
    policy = load_policy("log_policy.yaml")

    # Policy pass: collect violations and a map for overriding categories
    viol_rows = []
    pol_map = {}  # (file,line,message) -> (category, severity, rule_id)
    if policy:
        for _, r in df.iterrows():
            matched, rid, cat, sev, desc, suggest = eval_policy_row(r, policy)
            if matched:
                key = (r["file"], r["line"], r["message_template"])
                pol_map[key] = (cat, sev, rid)
                viol_rows.append({
                    "file": r["file"],
                    "line": r["line"],
                    "level": r["level"],
                    "rule_id": rid,
                    "category": cat,
                    "severity": sev,
                    "description": desc,
                    "suggest": suggest,
                    "message": r["message_template"],
                    "bytes": r["message_bytes"],
                })

    # Heuristics + optional LLM
    cats, reasons = [], []
    use_openai = bool(os.getenv("OPENAI_API_KEY"))
    for _, r in df.iterrows():
        # If policy already matched, prefer it
        key = (r["file"], r["line"], r["message_template"])
        if key in pol_map:
            cat, _sev, rid = pol_map[key]
            cats.append(cat)
            reasons.append(f"policy:{rid}")
            continue

        c, reason = classify_row(r)
        if c is None and use_openai:
            code_context = f"{r['file']}:{r['line']}  msg={r['message_template']}"
            judged_c, judged_reason = llm_judge(r["message_template"], r["level"], code_context)
            if judged_c is not None:
                c, reason = judged_c, judged_reason
        if c is None:
            c, reason = "ok", reason
        cats.append(c)
        reasons.append(reason)

    df["category"] = cats
    df["category_reason"] = reasons

    # Byte totals per category (answers “how many bytes each kind of log has”)
    agg = (
        df.groupby("category", dropna=False)["message_bytes"]
        .sum()
        .reset_index()
        .sort_values("message_bytes", ascending=False)
    )

    # Per-file breakdown for problematic categories
    problem_cats = {"bad_logs", "bad_format_logs", "unnecessary_logs"}
    bad_df = df[df["category"].isin(problem_cats)]
    per_file = (
        bad_df.groupby(["file", "category"])
        .agg(logs=("message_template", "count"), bytes=("message_bytes", "sum"))
        .reset_index()
    )

    # Artifacts
    df.to_csv("logs_classified.csv", index=False)
    agg.to_csv("logs_bytes_per_category.csv", index=False)
    per_file.to_csv("logs_per_file.csv", index=False)

    # Policy violations CSV
    if policy:
        viol_df = pd.DataFrame(viol_rows)
        if len(viol_df):
            viol_df.to_csv("logs_policy_violations.csv", index=False)
        else:
            pd.DataFrame(columns=[
                "file","line","level","rule_id","category","severity","description","suggest","message","bytes"
            ]).to_csv("logs_policy_violations.csv", index=False)

    # Console report
    print("\n=== Bytes per category ===")
    print(tabulate(agg, headers="keys", tablefmt="github", showindex=False))

    print("\n=== Problem logs (grouped by file & category) ===")
    if len(per_file):
        print(
            tabulate(
                per_file.sort_values(["bytes", "logs"], ascending=False),
                headers="keys",
                tablefmt="github",
                showindex=False,
            )
        )
    else:
        print("None 🎉")

    if policy:
        print("\n=== Policy violations ===")
        if len(viol_rows):
            vdf = pd.DataFrame(viol_rows).sort_values(["severity","bytes"], ascending=[False, False])
            print(tabulate(vdf.head(50), headers="keys", tablefmt="github", showindex=False))
            print("(Full list written to logs_policy_violations.csv)")
        else:
            print("None 🎉")

    print("\nArtifacts:")
    print(" - logs_classified.csv")
    print(" - logs_bytes_per_category.csv")
    print(" - logs_per_file.csv")
    if policy:
        print(" - logs_policy_violations.csv")

    # CI fail if severity threshold reached
    if policy and os.getenv("CI", "").lower() == "true":
        thr = SEVERITY_ORDER.get(policy["fail_on_severity"], 2)
        if os.path.exists("logs_policy_violations.csv"):
            _dfv = pd.read_csv("logs_policy_violations.csv")
            if len(_dfv) and _dfv["severity"].map(lambda s: SEVERITY_ORDER.get(str(s), 0)).max() >= thr:
                print(f"\nCI FAIL: violations at or above severity '{policy['fail_on_severity']}'", file=sys.stderr)
                sys.exit(1)

if __name__ == "__main__":
    main()
