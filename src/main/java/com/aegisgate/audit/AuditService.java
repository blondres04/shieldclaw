package com.aegisgate.audit;

import java.util.Optional;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final PullRequestRepository pullRequestRepository;

    public Optional<PullRequestEntity> getNextPendingAudit() {
        return pullRequestRepository.findFirstByStatus(AuditStatus.PENDING_AUDIT);
    }

    @Transactional
    public PullRequestEntity evaluateDecision(String prId, AuditDecisionRequest request) {
        PullRequestEntity entity = pullRequestRepository.findById(prId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "PR not found"));

        if (request.isApproved() && entity.isPoisoned()) {
            entity.setStatus(AuditStatus.AUDIT_FAILED_MISSED_THREAT);
        } else if (!request.isApproved() && !entity.isPoisoned()) {
            entity.setStatus(AuditStatus.AUDIT_FAILED_FALSE_POSITIVE);
        } else {
            entity.setStatus(AuditStatus.AUDIT_PASSED);
        }

        return pullRequestRepository.save(entity);
    }
}
