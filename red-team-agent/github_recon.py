"""
ShieldClaw GitHub Reconnaissance Module
Fetches Pull Request diffs from GitHub for live payload analysis.
"""

import os
from typing import Optional

from dotenv import load_dotenv
from github import Auth, Github, GithubException


class GitHubRecon:
    """Reads PR diffs from GitHub using a Personal Access Token."""

    def __init__(self) -> None:
        load_dotenv()
        token = os.environ.get("GITHUB_PAT", "")
        if not token or token == "your_token_here":
            raise ValueError(
                "GITHUB_PAT is not configured. "
                "Set a valid token in the .env file."
            )
        self._client = Github(auth=Auth.Token(token))

    def get_pr_diff(self, repo_name: str, pr_number: int) -> Optional[str]:
        """Fetch the unified diff for a Pull Request.

        Args:
            repo_name: Full repository slug, e.g. "owner/repo".
            pr_number: The PR number to fetch.

        Returns:
            The combined patch text of all changed files, or None on failure.
        """
        try:
            repo = self._client.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            files = pr.get_files()

            patches: list[str] = []
            for f in files:
                header = f"--- a/{f.filename}\n+++ b/{f.filename}"
                patch = f.patch if f.patch else "(binary or empty change)"
                patches.append(f"{header}\n{patch}")

            if not patches:
                print(f"[!] PR #{pr_number} in {repo_name} has no file changes")
                return None

            diff = "\n\n".join(patches)
            print(f"[+] Fetched diff for {repo_name}#{pr_number} "
                  f"({len(patches)} file(s), {len(diff)} chars)")
            return diff

        except GithubException as e:
            status = e.status if hasattr(e, "status") else "unknown"
            print(f"[!] GitHub API error (HTTP {status}): {e.data}")
            return None
        except Exception as e:
            print(f"[!] Failed to fetch PR diff: {e}")
            return None

    def close(self) -> None:
        self._client.close()


if __name__ == "__main__":
    recon = GitHubRecon()
    try:
        result = recon.get_pr_diff("octocat/Hello-World", 1)
        if result:
            print(result[:500])
    finally:
        recon.close()
