import json
import sys

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

    if len(vulnerabilities) == 0:
        summary_lines.append("✅ No vulnerabilities found.")

    return "\n".join(summary_lines)

if __name__ == "__main__":
    input_file = sys.argv[1]
    output_file = "scripts/snyk-summary.txt"

    with open(input_file, "r") as f:
        data = json.load(f)

    summary = summarize_vulnerabilities(data)

    with open(output_file, "w") as f:
        f.write(summary + "\n")
