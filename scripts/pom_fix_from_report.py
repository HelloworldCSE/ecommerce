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
    prompt = f"""You are an expert in Java, Spring Boot, and Maven dependency management.

You are given:
1. A summary of vulnerabilities detected in a pom.xml file.
2. The original pom.xml content of a Spring Boot project.

Your task:
- Update the pom.xml to fix all listed vulnerabilities.
- Ensure the resulting pom.xml maintains compatibility with Spring Boot.
- Avoid downgrading essential Spring Boot dependencies unless necessary.
- Use the Spring Boot BOM (Bill of Materials) if applicable.
- Ensure that the fixed pom.xml will not break the build or runtime behavior of a standard Spring Boot application.
- Do not remove required dependencies such as spring-boot-starter or other autoconfigured modules.

Return only the updated full pom.xml content — do not explain anything.

### Vulnerability Summary:
{summary}

### Original pom.xml:
{pom_content}

### Updated and Compatible pom.xml (FULL, READY TO USE):"""

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
