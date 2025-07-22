import sys
import json

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
        
        summary_lines.append(
            f"- {severity} - {vuln_id} ({title}) in `{package}@{version}` via `{from_path}` (file: `{file_path}`)"
        )

    if len(vulnerabilities) == 0:
        summary_lines.append("✅ No vulnerabilities found.")

    return "\n".join(summary_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python summarize_snyk_report.py <path-to-json>")
        sys.exit(1)

    json_path = sys.argv[1]

    try:
        with open(json_path, "r") as f:
            report_json = json.load(f)
    except json.JSONDecodeError:
        print("Invalid JSON input.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {json_path}")
        sys.exit(1)

    summary = summarize_vulnerabilities(report_json)

    with open("scripts/snyk-summary.txt", "w") as out_file:
        out_file.write(summary)

if __name__ == "__main__":
    main()
