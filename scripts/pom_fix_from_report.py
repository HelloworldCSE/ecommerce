import os
import sys
import re
import requests
from github import Github, GithubException

def read_summary(summary_file: str) -> list:
    with open(summary_file, 'r') as f:
        return [line.strip() for line in f if line.strip().startswith("- ")]

def extract_artifact_and_version(line: str) -> tuple:
    match = re.search(r'`([^@]+)@([^`]+)`', line)
    if match:
        return match.group(1), match.group(2)
    return None, None

def get_pom_content(path: str) -> str:
    with open(path, 'r') as f:
        return f.read()

def suggest_fix(api_key: str, artifact: str, version: str) -> str:
    prompt = f"""
You are an expert in secure Maven dependency management.

A Maven project is currently using a vulnerable dependency:
Artifact: {artifact}
Current version: {version}

Suggest the safest newer version (only version number) that fixes known vulnerabilities.
Do not explain. Only return the version.
"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    body = {
        "model": "mistral-small",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    response = requests.post("https://api.mistral.ai/v1/chat/completions", headers=headers, json=body)
    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"].strip()
    else:
        print("Mistral API error:", response.text)
        return None

def update_pom_versions(pom_path: str, updates: list):
    content = get_pom_content(pom_path)
    for artifact, old_version, new_version in updates:
        pattern = f"<artifactId>{artifact}</artifactId>\\s*<version>{old_version}</version>"
        replacement = f"<artifactId>{artifact}</artifactId>\n            <version>{new_version}</version>"
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    with open("pom1.xml", "w") as f:
        f.write(content)

def create_branch_and_pr(repo_name: str, token: str):
    g = Github(token)
    repo = g.get_repo(repo_name)
    base = repo.get_branch("main")
    branch_name = "fix/snyk-auto-fix"

    # Create the branch if it doesn’t exist
    try:
        repo.get_git_ref(f"heads/{branch_name}")
        print(f"🔁 Branch '{branch_name}' already exists.")
    except GithubException:
        print(f"🌿 Creating branch '{branch_name}' from 'main'")
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)

    # Create or update pom1.xml in the branch
    try:
        contents = repo.get_contents("pom1.xml", ref=branch_name)
        repo.update_file(
            path="pom1.xml",
            message="fix: update vulnerable dependencies [auto]",
            content=open("pom1.xml").read(),
            sha=contents.sha,
            branch=branch_name
        )
        print("📝 Updated existing pom1.xml in branch.")
    except GithubException:
        repo.create_file(
            path="pom1.xml",
            message="fix: update vulnerable dependencies [auto]",
            content=open("pom1.xml").read(),
            branch=branch_name
        )
        print("📄 Created pom1.xml in branch.")

    # Create PR if it doesn’t exist
    pulls = repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch_name}", base="main")
    if pulls.totalCount == 0:
        repo.create_pull(
            title="Auto PR: Fix Snyk Vulnerabilities in pom.xml",
            body="This PR updates vulnerable dependencies based on Snyk scan and Mistral suggestions.",
            head=branch_name,
            base="main"
        )
        print("✅ Pull request created.")
    else:
        print("🔁 PR already exists.")

if __name__ == "__main__":
    summary_file = sys.argv[1]
    pom_path = "pom.xml"

    summary_lines = read_summary(summary_file)
    mistral_key = os.environ.get("MISTRAL_API_KEY")
    github_token = os.environ.get("PERSONAL_ACCESS_TOKEN")
    repo = os.environ.get("GITHUB_REPO")

    updates = []
    for line in summary_lines:
        artifact, version = extract_artifact_and_version(line)
        if artifact and version:
            fixed_version = suggest_fix(mistral_key, artifact, version)
            if fixed_version:
                updates.append((artifact, version, fixed_version))

    if updates:
        update_pom_versions(pom_path, updates)
        create_branch_and_pr(repo, github_token)
        print("✅ Fix PR created successfully.")
    else:
        print("ℹ️ No actionable updates found.")
