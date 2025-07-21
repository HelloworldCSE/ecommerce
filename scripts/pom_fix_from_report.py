import os
import requests
import json
from github import Github
from github.ContentFile import ContentFile
from datetime import datetime

# Environment variables
GITHUB_TOKEN = os.getenv("PERSONAL_ACCESS_TOKEN")
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
GITHUB_REPO = os.getenv("GITHUB_REPO")
BRANCH_NAME = f"fix/pom-update-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
POM_FILE_PATH = "pom.xml"

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

# ---------- Prompt Setup for Mistral Fixer ----------
SYSTEM_PROMPT = (
    "You are an expert Java Maven developer. "
    "Your task is to fix vulnerable dependencies in the provided pom.xml based on the summary of Snyk vulnerabilities.\n"
    "Your fix must:\n"
    "- Upgrade each dependency only once.\n"
    "- Avoid duplicating <dependency> entries.\n"
    "- Preserve correct pom.xml structure.\n"
    "- Output only the complete corrected pom.xml content as valid XML without explanation or markdown."
)

def get_summary_text(summary_path: str) -> str:
    with open(summary_path, "r") as file:
        return file.read().strip()

def get_fixed_pom(summary_text: str) -> str:
    headers = {
        "Authorization": f"Bearer {MISTRAL_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "mistral-small",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": summary_text}
        ]
    }
    response = requests.post(MISTRAL_API_URL, headers=headers, json=data)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"].strip()

def commit_fixed_pom_to_github(fixed_pom: str):
    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(GITHUB_REPO)

    source = repo.get_branch("main")
    repo.create_git_ref(ref=f"refs/heads/{BRANCH_NAME}", sha=source.commit.sha)

    pom_file: ContentFile = repo.get_contents(POM_FILE_PATH, ref="main")

    repo.update_file(
        path=POM_FILE_PATH,
        message="fix: update vulnerable dependencies in pom.xml",
        content=fixed_pom,
        sha=pom_file.sha,
        branch=BRANCH_NAME,
    )

    repo.create_pull(
        title="fix: resolve Snyk vulnerabilities in pom.xml",
        body="This PR updates vulnerable dependencies as per latest Snyk scan.",
        head=BRANCH_NAME,
        base="main",
    )

if __name__ == "__main__":
    summary_text = get_summary_text("scripts/snyk-summary.txt")
    fixed_pom = get_fixed_pom(summary_text)
    commit_fixed_pom_to_github(fixed_pom)
    print("✅ Pull request created with fixed pom.xml.")
