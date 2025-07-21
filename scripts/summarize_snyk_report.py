import sys
import json

def summarize_vulnerabilities(report_json):
    summary_lines = ["# Snyk Scan Summary\n"]
    projects = report_json.get("runs", [])

    for project in projects:
        tool = project.get("tool", {}).get("driver", {}).get("name", "Snyk")
        results = project.get("results", [])

        for result in results:
            level = result.get("level", "UNKNOWN").upper()
            vuln_id = result.get("ruleId", "N/A")
            message = result.get("message", {}).get("text", "No message provided.")
            location = result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "Unknown file")

            summary_lines.append(f"- {level} - {vuln_id} in `{location}`: {message}")

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

    with open("scripts/snyk_summary.txt", "w") as out_file:
        out_file.write(summary)

if __name__ == "__main__":
    main()
