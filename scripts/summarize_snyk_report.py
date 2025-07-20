#!/usr/bin/env python3

import json
import sys
import os
from datetime import datetime


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


def create_vulnerability_report(vulnerability_data):
    lines = []
    lines.append(f"Snyk Vulnerability Report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    for vuln in vulnerability_data:
        lines.append(f"Project: {vuln['project']}")
        lines.append(f"- ID: {vuln['id']}")
        lines.append(f"- Title: {vuln['title']}")
        lines.append(f"- Severity: {vuln['severity']}")
        lines.append(f"- Package: {vuln['package']} ({vuln['version']})")
        lines.append(f"- From: {' > '.join(vuln['from'])}")
        if vuln["cve"]:
            lines.append(f"- CVEs: {', '.join(vuln['cve'])}")
        if vuln["fixed_in"]:
            lines.append(f"- Fixed in: {', '.join(vuln['fixed_in'])}")
        lines.append(f"- Upgradable: {'Yes' if vuln['is_upgradable'] else 'No'}")
        lines.append(f"- Patchable: {'Yes' if vuln['is_patchable'] else 'No'}")
        if vuln["urls"]:
            lines.append("- References:")
            for url in vuln["urls"][:3]:
                lines.append(f"  - {url}")
        if vuln["description"]:
            lines.append(f"- Description: {vuln['description'][:500]}")
        lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python snyk_vuln_report.py <path/to/snyk-results.json>")

    input_file = sys.argv[1]
    try:
        projects = load_snyk_results(input_file)
        all_vulns = []
        for project in projects:
            all_vulns.extend(extract_vulnerabilities(project))

        os.makedirs("scripts", exist_ok=True)
        report_content = create_vulnerability_report(all_vulns)
        with open("scripts/snyk-vulnerabilities.txt", "w", encoding="utf-8") as f:
            f.write(report_content)
    except Exception as e:
        fallback = f"Failed to process Snyk file: {str(e)}"
        os.makedirs("scripts", exist_ok=True)
        with open("scripts/snyk-vulnerabilities.txt", "w", encoding="utf-8") as f:
            f.write(fallback)
        sys.exit(1)


if __name__ == "__main__":
    main()
