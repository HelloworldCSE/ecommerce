import sys
import json
from pathlib import Path

def summarize_vulnerabilities(report_json):
    summary_lines = ["# Snyk Scan Summary\n"]

    vulnerabilities = report_json.get("vulnerabilities", [])
    file_path = report_json.get("displayTargetFile", "Unknown file")

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "unknown").upper()
        vuln_id = vuln.get("id", "N/A")
        title = vuln.get("title", "No title")
        package = vuln.get("packageName", "Unknown package")
        version = vuln.get("version", "")
        from_path = " > ".join(vuln.get("from", [])) if vuln.get("from") else "Unknown path"
        summary_lines.append(f"- {severity} - {vuln_id} ({title}) in `{package}@{version}` via `{from_path}` (file: `{file_path}`)")

    if not vulnerabilities:
        summary_lines.append("✅ No vulnerabilities found.")

    return "\n".join(summary_lines)

if __name__ == "__main__":
    input_file = sys.argv[1]
    output_file = "scripts/snyk-summary.txt"

    try:
        with open(input_file, "r") as f:
            report_json = json.load(f)
        summary = summarize_vulnerabilities(report_json)
    except Exception as e:
        summary = "# Snyk Scan Summary\nSummary generation failed.\nError: " + str(e)

    Path(output_file).write_text(summary)
