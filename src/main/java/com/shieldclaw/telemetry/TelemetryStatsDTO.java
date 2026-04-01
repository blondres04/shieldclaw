package com.shieldclaw.telemetry;

import java.util.Map;

public record TelemetryStatsDTO(
        Map<String, Long> statusCounts, Long verifiedExploits, Long failedExploits) {}
