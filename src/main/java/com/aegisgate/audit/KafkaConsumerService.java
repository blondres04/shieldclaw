package com.aegisgate.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class KafkaConsumerService {

    private final PullRequestRepository pullRequestRepository;

    @KafkaListener(topics = "audit.pr.ingested", groupId = "aegis-group")
    public void consume(PRPayloadDTO payload) {
        log.info("Consumed PR payload: {}", payload);

        PullRequestEntity entity = new PullRequestEntity();
        entity.setPrId(payload.prId());
        entity.setThreatCategory(payload.threatCategory());
        entity.setPoisoned(payload.isPoisoned());
        entity.setOriginalSnippet(payload.originalSnippet());
        entity.setPoisonedSnippet(payload.poisonedSnippet());
        entity.setAiJustificationGroundTruth(payload.aiJustificationGroundTruth());
        entity.setStatus(AuditStatus.PENDING_AUDIT);

        pullRequestRepository.save(entity);
        log.info("Persisted PR {} with status PENDING_AUDIT", payload.prId());
    }
}
