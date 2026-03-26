"""
Pydantic data models for sanitisation results and audit logging.
Built by Vaishali Mehmi using Claude AI + Anthropic Agents
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


# ============================================================================
# INPUT: Document from BUILD_01 (Ingestion)
# ============================================================================

class IngestedDocument(BaseModel):
    """Document as ingested from BUILD_01"""
    id: str = Field(..., description="UUID of the document")
    source_type: str = Field(..., description="Source: rss, pdf, or web")
    title: str = Field(..., description="Document title")
    summary: str = Field(..., description="Claude AI summary (3 sentences)")
    ingested_at: str = Field(..., description="ISO timestamp when ingested")


# ============================================================================
# OUTPUT: Sanitisation Result (extends ingested document)
# ============================================================================

class SanitisationResult(BaseModel):
    """Document after sanitisation processing"""
    id: str = Field(..., description="UUID of the document")
    source_type: str = Field(..., description="Source: rss, pdf, or web")
    title: str = Field(..., description="Document title (may be redacted)")
    summary: str = Field(..., description="Document summary (may be redacted)")
    ingested_at: str = Field(..., description="ISO timestamp when ingested")

    # Sanitisation-specific fields
    sanitisation_status: str = Field(
        ...,
        description="passed, passed_with_redactions, or failed"
    )
    failures: List[str] = Field(
        default_factory=list,
        description="List of injection patterns that failed (if any)"
    )
    pii_detected: List[str] = Field(
        default_factory=list,
        description="List of PII types detected: email, uk_phone, sort_code, ni_number"
    )


# ============================================================================
# AUDIT LOG RECORD
# ============================================================================

class AuditRecord(BaseModel):
    """Single entry in the append-only audit log"""
    timestamp: str = Field(..., description="ISO timestamp when event occurred")
    document_id: str = Field(..., description="UUID of the affected document")
    event_type: str = Field(
        ...,
        description="Event type: INJECTION_DETECTED, PII_DETECTED, PII_REDACTED, PASS, UNKNOWN"
    )
    pattern_matched: Optional[str] = Field(
        default=None,
        description="Pattern name that matched (e.g., sql_injection, xss)"
    )
    payload_snippet: Optional[str] = Field(
        default=None,
        description="First 100 characters of malicious payload (truncated for storage)"
    )
    severity: str = Field(
        ...,
        description="Severity level: CRITICAL, HIGH, MEDIUM, LOW"
    )
    source_type: str = Field(
        default="unknown",
        description="Source type of the document"
    )

    @staticmethod
    def create_injection_detected(
        document_id: str,
        pattern: str,
        payload: str,
        severity: str,
        source_type: str = "unknown"
    ) -> "AuditRecord":
        """Factory: Create audit record for injection detection"""
        return AuditRecord(
            timestamp=datetime.utcnow().isoformat() + "Z",
            document_id=document_id,
            event_type="INJECTION_DETECTED",
            pattern_matched=pattern,
            payload_snippet=payload[:100],  # Truncate for storage
            severity=severity,
            source_type=source_type
        )

    @staticmethod
    def create_pii_detected(
        document_id: str,
        pattern: str,
        payload: str,
        source_type: str = "unknown"
    ) -> "AuditRecord":
        """Factory: Create audit record for PII detection"""
        return AuditRecord(
            timestamp=datetime.utcnow().isoformat() + "Z",
            document_id=document_id,
            event_type="PII_DETECTED",
            pattern_matched=pattern,
            payload_snippet=payload[:100],
            severity="MEDIUM",
            source_type=source_type
        )

    @staticmethod
    def create_pii_redacted(
        document_id: str,
        patterns: List[str],
        source_type: str = "unknown"
    ) -> "AuditRecord":
        """Factory: Create audit record for PII redaction"""
        return AuditRecord(
            timestamp=datetime.utcnow().isoformat() + "Z",
            document_id=document_id,
            event_type="PII_REDACTED",
            pattern_matched=", ".join(patterns),
            payload_snippet=None,
            severity="LOW",
            source_type=source_type
        )

    @staticmethod
    def create_pass(
        document_id: str,
        source_type: str = "unknown"
    ) -> "AuditRecord":
        """Factory: Create audit record for document that passed all checks"""
        return AuditRecord(
            timestamp=datetime.utcnow().isoformat() + "Z",
            document_id=document_id,
            event_type="PASS",
            pattern_matched=None,
            payload_snippet=None,
            severity="LOW",
            source_type=source_type
        )


# ============================================================================
# PIPELINE REPORT (Final output)
# ============================================================================

class SanitisationReport(BaseModel):
    """Final sanitisation report (JSON output)"""
    generated_at: str = Field(..., description="ISO timestamp when report generated")
    input_count: int = Field(..., description="Total documents processed")
    passed_count: int = Field(..., description="Documents passed all checks")
    failed_count: int = Field(..., description="Documents that failed checks")
    passed_with_redactions_count: int = Field(
        ...,
        description="Documents passed but with PII redacted"
    )
    documents: List[SanitisationResult] = Field(
        ...,
        description="All documents with sanitisation status"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "generated_at": "2026-03-25T10:23:50Z",
                "input_count": 40,
                "passed_count": 36,
                "failed_count": 2,
                "passed_with_redactions_count": 2,
                "documents": [
                    {
                        "id": "uuid-001",
                        "source_type": "rss",
                        "title": "GSK Q4 Results",
                        "summary": "GSK reported Q4 earnings...",
                        "ingested_at": "2026-03-25T10:20:00Z",
                        "sanitisation_status": "passed",
                        "failures": [],
                        "pii_detected": []
                    }
                ]
            }
        }


# ============================================================================
# STATISTICS (for dashboard)
# ============================================================================

class SanitisationStats(BaseModel):
    """Summary statistics for dashboard integration"""
    total_documents: int
    passed: int
    failed: int
    passed_with_redactions: int
    injection_patterns_detected: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of each injection pattern detected"
    )
    pii_patterns_detected: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of each PII pattern detected"
    )

    @property
    def pass_rate(self) -> float:
        """Percentage of documents that passed (including redacted)"""
        if self.total_documents == 0:
            return 0.0
        return ((self.passed + self.passed_with_redactions) / self.total_documents) * 100
