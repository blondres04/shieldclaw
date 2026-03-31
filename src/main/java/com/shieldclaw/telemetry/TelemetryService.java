package com.shieldclaw.telemetry;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.shieldclaw.audit.AuditStatus;
import com.shieldclaw.audit.PullRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TelemetryService {

    private final PullRequestRepository pullRequestRepository;

    public TelemetryStatsDTO getAuditStatistics() {
        List<Object[]> rows = pullRequestRepository.countByStatus();

        Map<String, Long> statusCounts = new LinkedHashMap<>();
        for (Object[] row : rows) {
            String key = ((AuditStatus) row[0]).name();
            Long count = (Long) row[1];
            statusCounts.put(key, count);
        }

        return new TelemetryStatsDTO(statusCounts);
    }
}
