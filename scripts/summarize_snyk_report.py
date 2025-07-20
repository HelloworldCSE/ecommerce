#!/usr/bin/env python3

import json
import sys
import os


def load_snyk_results(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    if not content:
        return []

    try:
        data = json.loads(content)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        projects = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    projects.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return projects


def extract_vulnerabilities(project):
    details = []
    vulnerabilities = project.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        details.append({
            "project": project.get("projectName", "Unknown"),
            "id": vuln.get("id", ""),
            "title": vuln.get("title", ""),
            "severity": vuln.get("severity", ""),
            "package": vuln.get("package", ""),
            "version": vuln.get("version", ""),
            "from": vuln.get("from", []),
            "cve": vuln.get("identifiers", {}).get("CVE", []),
            "description": vuln.get("description", ""),
            "fixed_in": vuln.get("fixedIn", []),
            "is_upgradable": vuln.get("isUpgradable", False),
            "is_patchable": vuln.get("isPatchable", False),
            "urls": vuln.get("urls", [])
        })
    return details


def create_structured_json_report(vulnerability_data):
    return json.dumps(vulnerability_data, indent=2)


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    input_file = sys.argv[1]
    try:
        projects = load_snyk_results(input_file)
        all_vulns = []
        for project in projects:
            all_vulns.extend(extract_vulnerabilities(project))

        os.makedirs("scripts", exist_ok=True)
        report_content = create_structured_json_report(all_vulns)
        with open("scripts/snyk-vulnerabilities.json", "w", encoding="utf-8") as f:
            f.write(report_content)
    except Exception:
        os.makedirs("scripts", exist_ok=True)
        with open("scripts/snyk-vulnerabilities.json", "w", encoding="utf-8") as f:
            f.write("[]")
        sys.exit(1)


if __name__ == "__main__":
    main()
