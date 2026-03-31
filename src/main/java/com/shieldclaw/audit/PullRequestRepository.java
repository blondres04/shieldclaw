package com.shieldclaw.audit;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PullRequestRepository extends JpaRepository<PullRequestEntity, String> {

    @Query(value = "SELECT * FROM pull_requests WHERE status = 'PENDING_AUDIT' ORDER BY pr_id ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
            nativeQuery = true)
    Optional<PullRequestEntity> findNextPendingAndLock();

    List<PullRequestEntity> findAllByStatusAndUpdatedAtBefore(AuditStatus status, Instant cutoff);

    @Query("SELECT p.status, COUNT(p) FROM PullRequestEntity p GROUP BY p.status")
    List<Object[]> countByStatus();
}
