package com.shieldclaw.telemetry;

/**
 * Spring Data JPA projection for aggregated pull-request telemetry.
 * <p>
 * {@code statusCountsJson} is a JSON object mapping each {@link com.shieldclaw.audit.AuditStatus}
 * name to its row count (from {@code GROUP BY status}). The empirical fields are totals across
 * all rows with {@code empirically_verified} exactly true or false (nulls excluded).
 */
public interface TelemetryStatsProjection {

    String getStatusCountsJson();

    Long getEmpiricallyVerifiedTrueCount();

    Long getEmpiricallyVerifiedFalseCount();
}
