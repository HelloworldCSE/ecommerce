import sys
import json

def summarize_vulnerabilities(report_json):
    summary_lines = ["# Snyk Scan Summary\n"]

    vulnerabilities = report_json.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "unknown").upper()
        vuln_id = vuln.get("id", "N/A")
        title = vuln.get("title", "No title")
        package = vuln.get("package", "Unknown package")
        version = vuln.get("version", "")
        from_path = " > ".join(vuln.get("from", [])) if vuln.get("from") else "Unknown path"
        file_path = vuln.get("file", "Unknown file")

        summary_lines.append(f"- {severity} - {vuln_id} ({title}) in `{package}@{version}` via `{from_path}` (file: `{file_path}`)")

    if len(summary_lines) == 1:
        summary_lines.append("✅ No vulnerabilities found.")

    return "\n".join(summary_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python summarize_snyk_report.py <path-to-json>")
        sys.exit(1)

    json_path = sys.argv[1]

    with open(json_path, "r") as f:
        try:
            report_json = json.load(f)
        except json.JSONDecodeError:
            print("Invalid JSON input.")
            sys.exit(1)

    summary = summarize_vulnerabilities(report_json)

    with open("scripts/snyk-summary.txt", "w") as out_file:
        out_file.write(summary)

if __name__ == "__main__":
    main()
