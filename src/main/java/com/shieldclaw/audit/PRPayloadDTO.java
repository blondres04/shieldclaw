package com.shieldclaw.audit;

public record PRPayloadDTO(
        String prId,
        String threatCategory,
        boolean isPoisoned,
        String originalSnippet,
        String poisonedSnippet,
        String aiJustificationGroundTruth,
        String status
) {}
