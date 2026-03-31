package com.aegisgate.audit;

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

    private boolean isPoisoned;

    @Column(columnDefinition = "TEXT")
    private String originalSnippet;

    @Column(columnDefinition = "TEXT")
    private String poisonedSnippet;

    @Column(columnDefinition = "TEXT")
    private String aiJustificationGroundTruth;

    @Enumerated(EnumType.STRING)
    private AuditStatus status;

    @UpdateTimestamp
    private Instant updatedAt;
}
