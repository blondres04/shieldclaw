package com.shieldclaw.audit;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.shieldclaw.telemetry.TelemetryStatsProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PullRequestRepository extends JpaRepository<PullRequestEntity, String> {

    @Query(value = "SELECT * FROM pull_requests WHERE status = 'PENDING_AUDIT' ORDER BY pr_id ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
            nativeQuery = true)
    Optional<PullRequestEntity> findNextPendingAndLock();

    List<PullRequestEntity> findAllByStatusAndUpdatedAtBefore(AuditStatus status, Instant cutoff);

    @Query("SELECT p.status, COUNT(p) FROM PullRequestEntity p GROUP BY p.status")
    List<Object[]> countByStatus();

    /**
     * Single-row aggregate: status histogram (JSON from {@code GROUP BY status}) plus global
     * counts where {@code empirically_verified} is true or false (SQL NULLs excluded).
     */
    @Query(
            value =
                    """
                    SELECT
                      (
                        SELECT COALESCE(json_object_agg(grouped.status, grouped.cnt), '{}')::text
                        FROM (
                          SELECT pr.status AS status, COUNT(*)::bigint AS cnt
                          FROM pull_requests pr
                          GROUP BY pr.status
                        ) grouped
                      ) AS "statusCountsJson",
                      (
                        SELECT COUNT(*)::bigint FROM pull_requests WHERE empirically_verified IS TRUE
                      ) AS "empiricallyVerifiedTrueCount",
                      (
                        SELECT COUNT(*)::bigint FROM pull_requests WHERE empirically_verified IS FALSE
                      ) AS "empiricallyVerifiedFalseCount"
                    """,
            nativeQuery = true)
    TelemetryStatsProjection aggregateTelemetryStats();
}
