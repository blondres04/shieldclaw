package com.aegisgate.audit;

public enum AuditStatus {
    PENDING_AUDIT,
    IN_REVIEW,
    AUDIT_PASSED,
    AUDIT_FAILED_FALSE_POSITIVE,
    AUDIT_FAILED_MISSED_THREAT
}
