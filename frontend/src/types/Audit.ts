export interface PullRequest {
  prId: string;
  threatCategory: string;
  isPoisoned: boolean;
  originalSnippet: string;
  poisonedSnippet: string;
  aiJustificationGroundTruth?: string;
  empiricallyVerified?: boolean;
}

export interface TelemetryStats {
  statusCounts: Record<string, number>;
}
