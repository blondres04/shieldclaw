package com.shieldclaw.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

@Entity
@Table(name = "pull_requests")
@Getter
@Setter
@NoArgsConstructor
public class PullRequestEntity {

    @Id
    private String prId;

    private String threatCategory;

    @JsonProperty("isPoisoned")
    private boolean isPoisoned;

    @Column(columnDefinition = "TEXT")
    private String originalSnippet;

    @Column(columnDefinition = "TEXT")
    private String poisonedSnippet;

    @Column(columnDefinition = "TEXT")
    @JsonProperty("aiJustificationGroundTruth")
    private String aiJustificationGroundTruth;

    @JsonProperty("empiricallyVerified")
    private Boolean empiricallyVerified;

    @Enumerated(EnumType.STRING)
    private AuditStatus status;

    @UpdateTimestamp
    private Instant updatedAt;
}
