"""Issue screening, rule-based analysis, patch generation and patch validation."""
import re

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

BLOCKED_PATH = re.compile(r"(^|/)(\.github|\.git)/|(^|/)\.env|package-lock\.json|yarn\.lock|secret", re.I)
DANGEROUS = re.compile(r"\b(eval|Function|fetch|XMLHttpRequest|require|import|child_process|process\.env|document\.cookie)\b")
MAX_CHANGED_LINES = 20


def _fix(rule, line):
    return (rule.get("sub") or rule["find"]).sub(rule["repl"], line, count=1)


def analyze(title: str, body: str, path: str, code: str) -> dict:
    text = f"{title}\n{body}"
    hits = sum(1 for p in INJECTION if p.search(text))
    low = text.lower()
    lines = code.split("\n")

    findings = []
    for i, line in enumerate(lines):
        for rule in RULES:
            if rule["find"].search(line):
                fn = "(top level)"
                for j in range(i, -1, -1):
                    m = re.search(r"function\s+(\w+)", lines[j])
                    if m:
                        fn = m.group(1)
                        break
                score = 1 + sum(k in low for k in rule["kw"]) + (2 if fn.lower() in low else 0)
                findings.append(dict(line=i, rule=rule, fn=fn, score=score))
    findings.sort(key=lambda f: -f["score"])

    out, changes = list(lines), []
    for f in findings:
        new = _fix(f["rule"], out[f["line"]])
        if new != out[f["line"]]:
            changes.append(dict(i=f["line"], o=out[f["line"]], n=new))
            out[f["line"]] = new
    patched = "\n".join(out)

    clean_path = path.strip()
    checks = [
        ("Path is not protected (CI, secrets, lockfiles, .git)",
         bool(clean_path) and not BLOCKED_PATH.search(clean_path)
         and ".." not in clean_path and not clean_path.startswith("/")),
        ("Only one file touched", True),
        (f"At most {MAX_CHANGED_LINES} lines changed", len(changes) <= MAX_CHANGED_LINES),
        ("No dangerous APIs introduced",
         not any(DANGEROUS.search(c["n"]) and not DANGEROUS.search(c["o"]) for c in changes)),
    ]
    return dict(
        screen_hits=hits,
        findings=[dict(rule=f["rule"]["id"], fn=f["fn"], line=f["line"] + 1,
                       confidence=min(95, 40 + f["score"] * 10), why=f["rule"]["why"])
                  for f in findings],
        patched=patched,
        changes=changes,
        checks=[[label, ok] for label, ok in checks],
        ok=bool(changes) and all(ok for _, ok in checks),
    )
