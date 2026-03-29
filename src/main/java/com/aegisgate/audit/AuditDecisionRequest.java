package com.aegisgate.audit;

public record AuditDecisionRequest(
        String selectedThreatCategory,
        boolean isApproved
) {}
