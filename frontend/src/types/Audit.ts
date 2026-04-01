export interface PullRequest {
  prId: string;
  threatCategory: string;
  isPoisoned: boolean;
  originalSnippet: string;
  poisonedSnippet: string;
  aiJustificationGroundTruth?: string;
}

export interface TelemetryStats {
  statusCounts: Record<string, number>;
}
