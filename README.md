# BUILD 02 — Deterministic Sanitisation
**VAF AM Series | Day: Monday (paired) | Build Time: ~1.5 hours**
*Built with Claude AI + Anthropic Agents | Asset Management*

---
## WHAT THIS BUILDS
Rule-based (not AI) content sanitisation: prompt injection detection, PII redaction, HTML stripping. Sits between every external data source and the Claude API. Produces a full audit log — FCA-grade.

## FILE STRUCTURE
```
BUILD_02_SANITISATION/
├── README.md
├── .env.example
├── pyproject.toml
├── run.py
├── src/
│   ├── sanitiser.py          ← SanitisationPipeline (main)
│   ├── filters/
│   │   ├── injection_filter.py
│   │   ├── pii_redactor.py
│   │   ├── html_stripper.py
│   │   └── length_validator.py
│   ├── audit_log.py
│   └── models.py
├── tests/
│   ├── test_injection_filter.py
│   └── test_pii_redactor.py
└── press_pack/PRESS_PACK.md
```

## QUICK START
```bash
git clone https://github.com/vm799/vaf-am-build-02
cd vaf-am-build-02
cp .env.example .env
uv sync
uv run python run.py
```

## KEY CODE — src/sanitiser.py
```python
"""
VAF AM Build 02 — Deterministic Sanitisation
Built by Vaishali Mehmi using Claude AI + Anthropic Agents
"""
import re
from datetime import datetime
from dataclasses import dataclass, field

INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"you are now", r"disregard (your|the) (system|previous)",
    r"pretend (you are|to be)", r"act as (a|an|if)",
    r"forget everything", r"system prompt:", r"\[INST\]",
]

PII_PATTERNS = {
    "email":      r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "uk_phone":   r"(\+44|0)[0-9\s]{9,12}",
    "uk_sort":    r"\d{2}-\d{2}-\d{2}",
    "uk_account": r"\b\d{8}\b",
    "ni_number":  r"[A-Z]{2}\d{6}[A-Z]",
}

@dataclass
class SanitisationReport:
    passed: bool
    actions: list[str] = field(default_factory=list)
    injection_attempts: int = 0
    pii_removed: int = 0
    original_len: int = 0
    sanitised_len: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)

class SanitisationPipeline:
    MAX_CHARS = 32000
    _compiled_injection = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
    _compiled_pii = {k: re.compile(v) for k, v in PII_PATTERNS.items()}

    def sanitise(self, content: str, doc_id: str = "") -> tuple[str, SanitisationReport]:
        actions, injection_count, pii_count = [], 0, 0
        text = content

        # Step 1: Length
        if len(text) > self.MAX_CHARS:
            text = text[:self.MAX_CHARS]
            actions.append("truncated_to_limit")

        # Step 2: Injection detection + neutralisation
        for pattern in self._compiled_injection:
            if pattern.search(text):
                text = pattern.sub("[FILTERED]", text)
                injection_count += 1
                actions.append(f"injection_neutralised:{pattern.pattern[:30]}")

        # Step 3: PII redaction
        for pii_type, pattern in self._compiled_pii.items():
            matches = pattern.findall(text)
            if matches:
                text = pattern.sub(f"[{pii_type.upper()}_REDACTED]", text)
                pii_count += len(matches)
                actions.append(f"pii_redacted:{pii_type}:{len(matches)}")

        # Step 4: HTML stripping
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL|re.IGNORECASE)
        text = re.sub(r'<[^>]+>', '', text)

        report = SanitisationReport(
            passed=injection_count == 0,
            actions=actions,
            injection_attempts=injection_count,
            pii_removed=pii_count,
            original_len=len(content),
            sanitised_len=len(text),
        )
        return text, report
```

## COLOSSUS QA CHECKLIST
- [ ] Patterns compiled once at class init (not per call)
- [ ] Audit log append-only — no updates (FCA requirement)
- [ ] `passed=False` → content NOT sent to Claude (enforced in run.py)
- [ ] Tests cover: clean, injection attempt, PII, Unicode bypass attempt
