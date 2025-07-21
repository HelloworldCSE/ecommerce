import os
import sys
import requests
from github import Github

MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_NAME = os.getenv("GITHUB_REPO")
SNYK_SUMMARY_PATH = sys.argv[1] if len(sys.argv) > 1 else "scripts/snyk_summary.txt"
POM_FILE = "pom.xml"

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
HEADERS = {
    "Authorization": f"Bearer {MISTRAL_API_KEY}",
    "Content-Type": "application/json"
}

def read_summary(file_path):
    with open(file_path, "r") as f:
        return f.read()

def read_pom():
    with open(POM_FILE, "r") as f:
        return f.read()

def get_fix_from_mistral(summary, pom_content):
    prompt = f"""You are an expert in Java and Maven.
You are given a Snyk vulnerability summary and the contents of a pom.xml file.
Update the pom.xml file to fix the vulnerabilities using the summary provided.

### Vulnerability Summary:
{summary}

### pom.xml:
{pom_content}

### Fixed pom.xml (ONLY THE NEW CONTENT, NO EXPLANATION):"""

    body = {
        "model": "mistral-small",
        "messages": [
            {"role": "system", "content": "You are a helpful AI that improves Java pom.xml files based on vulnerability summaries."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": 2048
    }

    response = requests.post(MISTRAL_API_URL, headers=HEADERS, json=body)
    response.raise_for_status()
    result = response.json()
    return result["choices"][0]["message"]["content"].strip()

def create_branch_and_commit(new_pom):
    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(REPO_NAME)

    branch = "mistral-snyk-fix"
    source = repo.get_branch("main")

    try:
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=source.commit.sha)
    except Exception as e:
        print(f"Branch creation might have failed: {e}")

    pom_path = POM_FILE
    pom_file = repo.get_contents(pom_path, ref=branch)
    repo.update_file(
        pom_path,
        "fix: update pom.xml based on Snyk vulnerabilities",
        new_pom,
        pom_file.sha,
        branch=branch
    )

    repo.create_pull(
        title="fix: auto-update pom.xml via Mistral AI",
        body="This PR includes automatic fixes to `pom.xml` based on Snyk vulnerabilities using Mistral AI.",
        head=branch,
        base="main"
    )

if __name__ == "__main__":
    summary_text = read_summary(SNYK_SUMMARY_PATH)
    pom_text = read_pom()
    fixed_pom = get_fix_from_mistral(summary_text, pom_text)
    create_branch_and_commit(fixed_pom)
