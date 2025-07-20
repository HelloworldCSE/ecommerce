#!/usr/bin/env python3

import json
import sys
import os
from datetime import datetime
from collections import defaultdict

def load_snyk_results(file_path):
    try:
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
    except FileNotFoundError:
        return []
    except Exception:
        return []

def extract_vulnerability_details(project):
    details = []
    vulnerabilities = project.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        details.append({
            'project_name': project.get('projectName', 'Unknown Project'),
            'id': vuln.get('id', ''),
            'title': vuln.get('title', ''),
            'severity': vuln.get('severity', ''),
            'package': vuln.get('package', ''),
            'version': vuln.get('version', ''),
            'from': vuln.get('from', []),
            'fixed_in': vuln.get('fixedIn', []),
            'cve': vuln.get('identifiers', {}).get('CVE', []),
            'is_upgradable': vuln.get('isUpgradable', False),
            'is_patchable': vuln.get('isPatchable', False),
            'description': vuln.get('description', ''),
            'urls': vuln.get('urls', [])
        })
    return details

def create_vulnerability_report(projects_data):
    lines = []
    lines.append(f"Snyk Vulnerability Report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    all_vulns = []
    for project in projects_data:
        all_vulns.extend(extract_vulnerability_details(project))
    for vuln in all_vulns:
        lines.append(f"Project: {vuln['project_name']}")
        lines.append(f"- ID: {vuln['id']}")
        lines.append(f"- Title: {vuln['title']}")
        lines.append(f"- Severity: {vuln['severity']}")
        lines.append(f"- Package: {vuln['package']} ({vuln['version']})")
        lines.append(f"- From: {' > '.join(vuln['from'])}")
        if vuln['cve']:
            lines.append(f"- CVEs: {', '.join(vuln['cve'])}")
        if vuln['fixed_in']:
            lines.append(f"- Fixed in: {', '.join(vuln['fixed_in'])}")
        lines.append(f"- Upgradable: {'Yes' if vuln['is_upgradable'] else 'No'}")
        lines.append(f"- Patchable: {'Yes' if vuln['is_patchable'] else 'No'}")
        if vuln['urls']:
            lines.append(f"- References:")
            for url in vuln['urls'][:3]:
                lines.append(f"  - {url}")
        if vuln['description']:
            desc = vuln['description'].strip().replace('\n', ' ')
            lines.append(f"- Description: {desc[:500]}")
        lines.append("")
    return "\n".join(lines)

def main():
    try:
        if len(sys.argv) < 2:
            sys.exit("Usage: python snyk_vulnerability_report.py <path/to/snyk-results.json>")
        input_file = sys.argv[1]
        os.makedirs("scripts", exist_ok=True)
        projects_data = load_snyk_results(input_file)
        report_content = create_vulnerability_report(projects_data)
        output_file = "scripts/snyk-vulnerabilities.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report_content)
    except Exception as e:
        try:
            os.makedirs("scripts", exist_ok=True)
            with open("scripts/snyk-vulnerabilities.txt", "w", encoding="utf-8") as f:
                f.write(f"Failed to generate report: {str(e)}")
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    main()
