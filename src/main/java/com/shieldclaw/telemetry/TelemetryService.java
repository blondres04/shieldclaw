package com.shieldclaw.telemetry;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shieldclaw.audit.PullRequestRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class TelemetryService {

    private static final TypeReference<Map<String, Object>> STATUS_COUNTS_RAW_TYPE =
            new TypeReference<>() {};

    private final PullRequestRepository pullRequestRepository;
    private final ObjectMapper objectMapper;

    public TelemetryStatsDTO getAggregateTelemetryStats() {
        TelemetryStatsProjection row = pullRequestRepository.aggregateTelemetryStats();

        Map<String, Long> statusCounts = parseStatusCounts(row.getStatusCountsJson());
        Long verifiedExploits = row.getEmpiricallyVerifiedTrueCount();
        Long failedExploits = row.getEmpiricallyVerifiedFalseCount();

        return new TelemetryStatsDTO(statusCounts, verifiedExploits, failedExploits);
    }

    private Map<String, Long> parseStatusCounts(String json) {
        if (json == null || json.isBlank()) {
            return Collections.emptyMap();
        }
        try {
            Map<String, Object> raw = objectMapper.readValue(json, STATUS_COUNTS_RAW_TYPE);
            if (raw == null || raw.isEmpty()) {
                return Collections.emptyMap();
            }
            Map<String, Long> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : raw.entrySet()) {
                Object v = e.getValue();
                long n = v instanceof Number ? ((Number) v).longValue() : 0L;
                out.put(e.getKey(), n);
            }
            return out;
        } catch (JsonProcessingException e) {
            log.warn("Failed to parse statusCountsJson; returning empty map: {}", e.getMessage());
            return Collections.emptyMap();
        }
    }
}
