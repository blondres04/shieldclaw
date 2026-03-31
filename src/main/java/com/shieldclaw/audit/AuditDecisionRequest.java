package com.shieldclaw.audit;

public record AuditDecisionRequest(
        String selectedThreatCategory,
        boolean isApproved
) {}
