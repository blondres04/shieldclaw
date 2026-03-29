export interface PullRequest {
  prId: string;
  threatCategory: string;
  originalSnippet: string;
  poisonedSnippet: string;
}

export interface TelemetryStats {
  statusCounts: Record<string, number>;
}
