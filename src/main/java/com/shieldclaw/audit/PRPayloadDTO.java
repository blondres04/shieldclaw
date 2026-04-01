package com.shieldclaw.audit;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PRPayloadDTO(
        String prId,
        String threatCategory,
        @JsonProperty("isPoisoned") boolean isPoisoned,
        String originalSnippet,
        String poisonedSnippet,
        @JsonProperty("aiJustificationGroundTruth") String aiJustificationGroundTruth,
        @JsonProperty("empiricallyVerified") Boolean empiricallyVerified,
        String status
) {}
