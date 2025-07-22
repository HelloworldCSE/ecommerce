import json
import sys

def summarize_vulnerabilities(data):
    summary_lines = ["# Snyk Scan Summary\n"]
    total_vulns = 0

    for project in data:
        project_name = project.get("projectName", "Unknown Project")
        file_path = project.get("displayTargetFile", "Unknown file")
        vulnerabilities = project.get("vulnerabilities", [])

        if not vulnerabilities:
            continue

        summary_lines.append(f"## {project_name} ({file_path})\n")

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").upper()
            vuln_id = vuln.get("id", "N/A")
            title = vuln.get("title", "No title")
            package = vuln.get("packageName", "Unknown package")
            version = vuln.get("version", "")
            from_path = " > ".join(vuln.get("from", [])) if vuln.get("from") else "Unknown path"

            summary_lines.append(
                f"- {severity} - {vuln_id} ({title}) in `{package}@{version}` via `{from_path}`"
            )
            total_vulns += 1

    if total_vulns == 0:
        summary_lines.append("✅ No vulnerabilities found.")

    return "\n".join(summary_lines)

if __name__ == "__main__":
    input_file = sys.argv[1]
    output_file = "scripts/snyk-summary.txt"

    with open(input_file, "r") as f:
        data = json.load(f)

    # Handle the case where `data` is an object instead of a list
    if isinstance(data, dict):
        data = [data]

    summary = summarize_vulnerabilities(data)

    with open(output_file, "w") as f:
        f.write(summary + "\n")
