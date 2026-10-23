"""Issue analysis, conservative rule-based fallback, and patch validation."""
import difflib
import re
from pathlib import PurePosixPath

RULES = [
    dict(id="off-by-one", find=re.compile(r"(\w+)\s*<=\s*(\w+)\.length"),
         repl=r"\1 < \2.length", why="Loop runs one iteration past the last index.",
         kw=["nan", "undefined", "index", "last", "length", "loop", "past"]),
    dict(id="loose-equality", find=re.compile(r"[^=!<>]==[^=]"),
         sub=re.compile(r"([^=!<>])==([^=])"), repl=r"\1===\2",
         why='Loose equality coerces types (for example "" == 0 is true).',
         kw=["equal", "coerc", "empty", "string", "zero", "true", "type"]),
    dict(id="parseInt-radix", find=re.compile(r"parseInt\(([^(),]+)\)"),
         repl=r"parseInt(\1, 10)", why="parseInt without a radix can misparse input.",
         kw=["parse", "int", "octal", "number"]),
]

INJECTION = [re.compile(p, re.I) for p in [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard .{0,30}(rules|instructions)",
    r"system prompt",
    r"\b(api[_ -]?key|token|password|secret)s?\b.{0,40}(upload|send|post|server)",
    r"(upload|send|post).{0,40}\b(api[_ -]?key|token|password|secret)",
    r"\.github/|\.env\b|rm -rf|curl |wget ",
]]
PROTECTED_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "cargo.lock", "composer.lock",
}
DANGEROUS = re.compile(
    r"\b(eval|Function|fetch|XMLHttpRequest|require|import|child_process|"
    r"process\.env|document\.cookie)\b"
)
MAX_CHANGED_LINES = 20


def _fix(rule, line):
    return (rule.get("sub") or rule["find"]).sub(rule["repl"], line, count=1)


def validate_path(path: str) -> bool:
    normalized = path.strip().replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    lowered = [part.lower() for part in parts]
    return bool(normalized) and not (
        normalized.startswith("/")
        or re.match(r"^[a-z]:", normalized, re.I)
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
        or any(ord(char) < 32 for char in normalized)
        or ":" in normalized
        or any(part in {".git", ".github"} for part in lowered)
        or any(part == ".env" or part.startswith(".env.") for part in lowered)
        or any("secret" in part for part in lowered)
        or any(part in PROTECTED_FILES for part in lowered)
    )


def validate_patch(path: str, original: str, patched: str) -> dict:
    diff = list(difflib.ndiff(original.splitlines(), patched.splitlines()))
    changed = sum(line.startswith(("- ", "+ ")) for line in diff)
    old_apis = DANGEROUS.findall(original)
    new_apis = DANGEROUS.findall(patched)
    api_counts = {name: old_apis.count(name) >= new_apis.count(name)
                  for name in set(old_apis + new_apis)}
    checks = [
        ("Path is not protected and contains no traversal", validate_path(path)),
        ("Patch changes at least one line", changed > 0),
        (f"At most {MAX_CHANGED_LINES} lines changed", changed <= MAX_CHANGED_LINES),
        ("No dangerous APIs introduced", all(api_counts.values())),
    ]
    return {
        "checks": [[label, passed] for label, passed in checks],
        "ok": all(passed for _, passed in checks),
        "changes": changed,
        "diff": "\n".join(difflib.unified_diff(
            original.splitlines(), patched.splitlines(),
            fromfile=f"a/{path}", tofile=f"b/{path}", lineterm=""
        )),
    }


def analyze_rules(title: str, body: str, path: str, code: str) -> dict:
    text = f"{title}\n{body}"
    low = text.lower()
    findings = []
    lines = code.split("\n")
    for i, line in enumerate(lines):
        for rule in RULES:
            if rule["find"].search(line):
                fn = "(top level)"
                for j in range(i, -1, -1):
                    match = re.search(r"function\s+(\w+)", lines[j])
                    if match:
                        fn = match.group(1)
                        break
                score = 1 + sum(keyword in low for keyword in rule["kw"])
                score += 2 if fn.lower() in low else 0
                findings.append({
                    "rule": rule["id"], "fn": fn, "line": i + 1,
                    "confidence": min(95, 40 + score * 10), "why": rule["why"],
                    "_score": score, "_rule": rule, "_index": i,
                })
    findings.sort(key=lambda finding: -finding["_score"])
    output = list(lines)
    for finding in findings:
        output[finding["_index"]] = _fix(
            finding["_rule"], output[finding["_index"]]
        )
    public_findings = [
        {key: value for key, value in finding.items() if not key.startswith("_")}
        for finding in findings
    ]
    return {
        "screen_hits": sum(bool(pattern.search(text)) for pattern in INJECTION),
        "findings": public_findings,
        "patched": "\n".join(output) if findings else code,
        "provider": "rules",
    }


def analyze_with_llm(title: str, body: str, path: str, code: str, llm) -> dict:
    result = llm.analyze(title, body, path, code)
    findings = result["findings"] if result["finding"] else []

    def bounded_int(value, default, lower, upper):
        try:
            return max(lower, min(upper, int(value)))
        except (TypeError, ValueError, OverflowError):
            return default

    normalized = []
    for finding in findings:
        normalized.append({
            "rule": str(finding.get("rule", "llm-analysis"))[:100],
            "fn": str(finding.get("fn", "(unspecified)"))[:100],
            "line": bounded_int(finding.get("line"), 1, 1, len(code.splitlines()) or 1),
            "confidence": bounded_int(finding.get("confidence"), 70, 0, 100),
            "why": str(finding.get("why", result.get("rationale", "")))[:1000],
        })
    patched = result.get("patched_code") if findings else code
    if not isinstance(patched, str):
        patched = code
    return {
        "screen_hits": sum(bool(pattern.search(f"{title}\n{body}")) for pattern in INJECTION),
        "findings": normalized,
        "patched": patched,
        "provider": "llm",
    }


def analyze(title: str, body: str, path: str, code: str, llm=None) -> dict:
    if llm is not None and llm.is_configured():
        result = analyze_with_llm(title, body, path, code, llm)
    else:
        result = analyze_rules(title, body, path, code)
    validation = validate_patch(path, code, result["patched"])
    result.update(validation)
    result["ok"] = bool(result["findings"]) and validation["ok"]
    return result
