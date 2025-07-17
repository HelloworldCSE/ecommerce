import json
from textwrap import wrap
from datetime import datetime

def format_description(desc):
    """Clean up Markdown formatting in descriptions"""
    if not desc:
        return "No description available"
    desc = desc.replace("## ", "").replace("\n\n", "\n").strip()
    return "\n".join(wrap(desc, width=80))

def parse_cvss_vector(vector):
    """Extract meaningful parts from CVSS vector"""
    if not vector:
        return "N/A"
    parts = vector.split("/")[3:]
    return ", ".join([p for p in parts if ":" in p])

def generate_report(vulnerabilities):
    report = []
    for vuln in vulnerabilities:
        entry = [
            f"Vulnerability ID: {vuln.get('id', 'N/A')}",
            f"Package: {vuln.get('packageName', vuln.get('moduleName', 'N/A'))}@{vuln.get('version', 'N/A')}",
            f"Severity: {vuln.get('severityWithCritical', vuln.get('severity', 'N/A')).upper()}",
            f"CVSS Score: {vuln.get('cvssScore', 'N/A')} (v{vuln.get('cvssVersion', '3.1')})",
            f"Published: {vuln.get('publicationTime', vuln.get('disclosureTime', 'N/A'))}",
            ""
        ]

        identifiers = vuln.get('identifiers', {})
        if identifiers:
            entry.extend([
                "Identifiers:",
                f"- CVEs: {', '.join(identifiers.get('CVE', ['N/A']))}",
                f"- CWEs: {', '.join(identifiers.get('CWE', ['N/A']))}",
                f"- GHSAs: {', '.join(identifiers.get('GHSA', ['N/A']))}",
                ""
            ])

        entry.extend([
            "Description:",
            format_description(vuln.get('description', 'No description available')),
            "",
            "Remediation:",
            f"Upgrade to: {', '.join(vuln.get('fixedIn', ['Not specified']))}",
            f"Upgrade path: {' -> '.join([str(x) for x in vuln.get('upgradePath', []) if x])}",
            ""
        ])

        if vuln.get('cvssDetails'):
            entry.append("CVSS Assessments:")
            for detail in vuln['cvssDetails']:
                entry.append(
                    f"- {detail.get('assigner', 'Unknown')}: {detail.get('cvssV3BaseScore', 'N/A')} "
                    f"({detail.get('severity', 'N/A')}, {detail.get('cvssV3Vector', 'N/A')})"
                )
            entry.append("")

        if vuln.get('references'):
            entry.append("References:")
            for ref in vuln['references']:
                entry.append(f"- {ref.get('title', 'Reference')}: {ref.get('url', 'N/A')}")
            entry.append("")

        report.append("\n".join(entry))
        report.append("=" * 80)
        report.append("")

    return "\n".join(report)

def process_snyk_data(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        with open(output_file, 'w') as f:
            f.write(f"Failed to read or parse input JSON: {str(e)}")
        return

    vulnerabilities = []
    if isinstance(data, dict):
        vulnerabilities = data.get('vulnerabilities', [])
    elif isinstance(data, list):
        for project in data:
            vulnerabilities.extend(project.get('vulnerabilities', []))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'low').lower()))

    report = generate_report(vulnerabilities)

    with open(output_file, 'w') as f:
        f.write(report)

    print(f"Generated vulnerability report with {len(vulnerabilities)} findings in {output_file}")

if __name__ == "__main__":
    process_snyk_data("snyk-results.json", "vulnerability-report.txt")
