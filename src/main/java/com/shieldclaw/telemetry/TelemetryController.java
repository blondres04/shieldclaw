package com.shieldclaw.telemetry;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class TelemetryController {

    private final TelemetryService telemetryService;

    /**
     * Aggregated audit telemetry (status histogram + empirical sandbox outcomes).
     * CORS is configured globally in {@link com.shieldclaw.security.SecurityConfig}.
     */
    @GetMapping("/audit/stats")
    public TelemetryStatsDTO getAuditStats() {
        return telemetryService.getAggregateTelemetryStats();
    }
}
