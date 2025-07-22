import sys
import json

def summarize_vulnerabilities(report_json):
    summary_lines = ["# Snyk Scan Summary\n"]
    vulnerabilities = []

    # Handle both single and multi-project reports
    if isinstance(report_json, list):  # Multi-project
        for project in report_json:
            vulnerabilities.extend(project.get("vulnerabilities", []))
    elif isinstance(report_json, dict):  # Single project
        vulnerabilities = report_json.get("vulnerabilities", [])

    if not vulnerabilities:
        summary_lines.append("✅ No vulnerabilities found.")
    else:
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            title = vuln.get("title", "Untitled")
            package = vuln.get("package", "unknown")
            version = vuln.get("version", "")
            summary_lines.append(f"- **{severity}** - {title} ({package}@{version})")

    return "\n".join(summary_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python summarize_snyk_report.py <path-to-json>")
        sys.exit(1)

    json_path = sys.argv[1]

    try:
        with open(json_path, "r") as f:
            report_json = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading or parsing JSON: {e}")
        sys.exit(1)

    summary = summarize_vulnerabilities(report_json)

    try:
        with open("scripts/snyk-summary.txt", "w") as out_file:
            out_file.write(summary)
        print("✅ Summary file generated.")
    except Exception as e:
        print(f"Error writing summary file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
