package com.aegisgate.audit;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PullRequestRepository extends JpaRepository<PullRequestEntity, String> {

    Optional<PullRequestEntity> findFirstByStatus(AuditStatus status);

    @Query("SELECT p.status, COUNT(p) FROM PullRequestEntity p GROUP BY p.status")
    List<Object[]> countByStatus();
}
