import os
import re
import shutil
import uuid

import git


class GitHubService:
    SCAN_BASE_DIR = "/tmp/scans"

    def __init__(self):
        os.makedirs(self.SCAN_BASE_DIR, exist_ok=True)

    def extract_repo_name(self, repo_url: str) -> str:
        cleaned = repo_url.rstrip("/").replace(".git", "")
        match = re.search(r"github\.com[/:]([^/]+)/([^/]+)$", cleaned)
        if match:
            return match.group(2)
        parts = cleaned.split("/")
        return parts[-1] if parts else "unknown-repo"

    def clone_repository(self, repo_url: str) -> tuple[str, str]:
        scan_id = str(uuid.uuid4())
        clone_path = os.path.join(self.SCAN_BASE_DIR, scan_id)

        if os.path.exists(clone_path):
            shutil.rmtree(clone_path)

        os.makedirs(clone_path, exist_ok=True)

        git.Repo.clone_from(repo_url, clone_path, depth=1)

        repo_name = self.extract_repo_name(repo_url)
        return clone_path, repo_name

    def cleanup_scan_directory(self, clone_path: str):
        if clone_path and os.path.exists(clone_path):
            shutil.rmtree(clone_path, ignore_errors=True)
