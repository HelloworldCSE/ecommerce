import os
import requests
import time
from github import Github

MISTRAL_API_KEY = os.environ["MISTRAL_API_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
REPO_NAME = os.environ["GITHUB_REPO"]
POM_FILE_PATH = os.environ.get("POM_FILE_PATH", "pom.xml")
SNYK_SUMMARY_PATH = os.environ.get("SNYK_SUMMARY_PATH", "scripts/snyk_summary.txt")

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

def read_summary(file_path):
    with open(file_path, "r") as f:
        return f.read()

def read_pom(file_path):
    with open(file_path, "r") as f:
        return f.read()

def generate_fixed_pom(vuln_summary, original_pom):
    system_prompt = (
        "You are a Java Maven security expert. Your job is to fix the vulnerable dependencies in the pom.xml "
        "based on the given Snyk vulnerability summary. Update only the necessary dependencies. Do not add comments or explanations."
    )

    user_prompt = (
        f"Snyk Vulnerability Summary:\n{vuln_summary}\n\nOriginal pom.xml:\n{original_pom}\n\n"
        "Please return the updated pom.xml with fixed dependency versions."
    )

    headers = {
        "Authorization": f"Bearer {MISTRAL_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "mistral-small",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.3
    }

    for attempt in range(3):
        try:
            response = requests.post(MISTRAL_API_URL, json=payload, headers=headers)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return content
        except Exception as e:
            print(f"Retry {attempt+1}/3 failed: {e}")
            time.sleep(2)
    raise RuntimeError("Failed to get response from Mistral API after 3 attempts.")

def write_fixed_pom(fixed_content):
    with open(POM_FILE_PATH, "w") as f:
        f.write(fixed_content)

def create_branch_and_pr(repo, token):
    g = Github(token)
    repository = g.get_repo(repo)
    base = repository.get_branch("main")
    branch_name = f"fix-pom-{int(time.time())}"

    ref = repository.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)

    pom_content = repository.get_contents(POM_FILE_PATH, ref="refs/heads/" + branch_name)
    with open(POM_FILE_PATH, "r") as f:
        updated_content = f.read()

    repository.update_file(
        path=POM_FILE_PATH,
        message="fix: update vulnerable dependencies in pom.xml",
        content=updated_content,
        sha=pom_content.sha,
        branch=branch_name
    )

    repository.create_pull(
        title="Fix: Vulnerable Dependencies in pom.xml",
        body="This PR addresses vulnerabilities as per Snyk report.",
        head=branch_name,
        base="main"
    )

if __name__ == "__main__":
    vuln_summary = read_summary(SNYK_SUMMARY_PATH)
    original_pom = read_pom(POM_FILE_PATH)
    fixed_pom = generate_fixed_pom(vuln_summary, original_pom)
    write_fixed_pom(fixed_pom)
    create_branch_and_pr(REPO_NAME, GITHUB_TOKEN)
