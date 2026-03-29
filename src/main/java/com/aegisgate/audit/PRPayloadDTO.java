package com.aegisgate.audit;

public record PRPayloadDTO(
        String prId,
        String threatCategory,
        boolean isPoisoned,
        String originalSnippet,
        String poisonedSnippet,
        String aiJustificationGroundTruth,
        String status
) {}
