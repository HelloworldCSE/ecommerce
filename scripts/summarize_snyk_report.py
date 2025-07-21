import sys
import json

def summarize_vulnerabilities(vuln_json):
    summary_lines = ["# Snyk Scan Summary\n"]
    projects = vuln_json.get("vulnerabilities", [])

    if not projects:
        summary_lines.append("✅ No vulnerabilities found.")
        return "\n".join(summary_lines)

    for vuln in projects:
        severity = vuln.get("severity", "unknown").upper()
        package = vuln.get("package", "unknown-package")
        version = vuln.get("version", "unknown-version")
        title = vuln.get("title", "No title provided")
        file_path = vuln.get("from", ["unknown-location"])[-1]

        summary_lines.append(
            f"- {severity} - {title} in `{package}@{version}` ({file_path})"
        )

    return "\n".join(summary_lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python summarize_snyk_report.py <path-to-json>")
        sys.exit(1)

    json_path = sys.argv[1]

    try:
        with open(json_path, "r") as f:
            report_json = json.load(f)
    except Exception as e:
        print(f"Failed to load JSON: {e}")
        sys.exit(1)

    summary = summarize_vulnerabilities(report_json)

    with open("scripts/snyk-summary.txt", "w") as out_file:
        out_file.write(summary)

if __name__ == "__main__":
    main()
