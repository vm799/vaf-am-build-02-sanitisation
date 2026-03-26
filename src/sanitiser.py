"""
VAF AM Build 02 — Deterministic Sanitisation
Built by Vaishali Mehmi using Claude AI + Anthropic Agents
github.com/vm799 | Asset Management Series
"""
import re
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"you are now",
    r"disregard (your|the) (system|previous)",
    r"pretend (you are|to be)",
    r"act as (a|an|if)",
    r"forget everything",
    r"new instruction[s]?:",
    r"system prompt:",
    r"\[INST\]",
    r"<\|im_start\|>",
    r"<\|system\|>",
    r"override (all )?instructions",
]

PII_PATTERNS = {
    "email":      r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "uk_phone":   r"(\+44|0)[0-9\s\-]{9,12}",
    "uk_sort":    r"\d{2}-\d{2}-\d{2}",
    "uk_account": r"\b\d{8}\b",
    "ni_number":  r"[A-Z]{2}\d{6}[A-Z]",
    "postcode":   r"[A-Z]{1,2}[0-9][0-9A-Z]?\s?[0-9][A-Z]{2}",
}


@dataclass
class SanitisationReport:
    passed: bool
    actions: list = field(default_factory=list)
    injection_attempts: int = 0
    pii_removed: int = 0
    original_len: int = 0
    sanitised_len: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)


class SanitisationPipeline:
    MAX_CHARS = 32000
    _compiled_injection = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
    _compiled_pii = {k: re.compile(v) for k, v in PII_PATTERNS.items()}

    def sanitise(self, content: str, doc_id: str = "") -> tuple:
        actions, injection_count, pii_count = [], 0, 0
        text = content

        # Step 1: Length
        if len(text) > self.MAX_CHARS:
            text = text[:self.MAX_CHARS]
            actions.append("truncated_to_limit")

        # Step 2: Injection detection
        for pattern in self._compiled_injection:
            if pattern.search(text):
                text = pattern.sub("[FILTERED]", text)
                injection_count += 1
                actions.append(f"injection_neutralised")

        # Step 3: PII redaction
        for pii_type, pattern in self._compiled_pii.items():
            matches = pattern.findall(text)
            if matches:
                text = pattern.sub(f"[{pii_type.upper()}_REDACTED]", text)
                pii_count += len(matches)
                actions.append(f"pii_redacted:{pii_type}:{len(matches)}")

        # Step 4: HTML stripping
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', '', text)

        # Step 5: Encoding normalise — remove null bytes and control chars
        text = text.replace('\x00', '').replace('\r', '\n')

        report = SanitisationReport(
            passed=injection_count == 0,
            actions=actions,
            injection_attempts=injection_count,
            pii_removed=pii_count,
            original_len=len(content),
            sanitised_len=len(text),
        )
        return text, report
