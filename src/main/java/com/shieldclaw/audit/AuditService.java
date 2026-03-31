package com.shieldclaw.audit;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

    private final PullRequestRepository pullRequestRepository;

    @Transactional
    public Optional<PullRequestEntity> getNextPendingAudit() {
        return pullRequestRepository.findNextPendingAndLock()
                .map(pr -> {
                    pr.setStatus(AuditStatus.IN_REVIEW);
                    return pullRequestRepository.save(pr);
                });
    }

    @Transactional
    public PullRequestEntity evaluateDecision(String prId, AuditDecisionRequest request) {
        PullRequestEntity entity = pullRequestRepository.findById(prId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "PR not found"));

        AuditStatus current = entity.getStatus();

        if (current == AuditStatus.PENDING_AUDIT) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "PR was reclaimed by the reaper — fetch a new audit");
        }

        if (current != AuditStatus.IN_REVIEW) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "PR has already been graded (status: " + current + ")");
        }

        if (request.isApproved() && entity.isPoisoned()) {
            entity.setStatus(AuditStatus.AUDIT_FAILED_MISSED_THREAT);
        } else if (!request.isApproved() && !entity.isPoisoned()) {
            entity.setStatus(AuditStatus.AUDIT_FAILED_FALSE_POSITIVE);
        } else {
            entity.setStatus(AuditStatus.AUDIT_PASSED);
        }

        return pullRequestRepository.save(entity);
    }

    @Scheduled(fixedRate = 300_000)
    @Transactional
    public void reapStaleReviews() {
        Instant cutoff = Instant.now().minus(10, ChronoUnit.MINUTES);
        List<PullRequestEntity> stale =
                pullRequestRepository.findAllByStatusAndUpdatedAtBefore(AuditStatus.IN_REVIEW, cutoff);

        if (!stale.isEmpty()) {
            log.warn("Reaping {} stale IN_REVIEW PR(s) back to PENDING_AUDIT", stale.size());
            stale.forEach(pr -> pr.setStatus(AuditStatus.PENDING_AUDIT));
            pullRequestRepository.saveAll(stale);
        }
    }
}
