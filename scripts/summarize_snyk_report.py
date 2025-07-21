import json
import sys
import os

def summarize_vulnerabilities(report_path: str, output_path: str = "scripts/snyk-summary.txt"):
    if not os.path.exists(report_path):
        print(f"❌ Report file not found: {report_path}")
        return

    with open(report_path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("❌ Invalid JSON in report file")
            return

    summary_lines = ["# Snyk Scan Summary", ""]

    if "vulnerabilities" not in data or not data["vulnerabilities"]:
        summary_lines.append("✅ No vulnerabilities found.")
    else:
        vulns = data["vulnerabilities"]
        for v in vulns:
            severity = v.get("severity", "unknown").upper()
            title = v.get("title", "No title")
            pkg = v.get("package", "unknown")
            version = v.get("version", "unknown")
            summary_lines.append(f"- **{severity}** - `{pkg}@{version}`: {title}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as out_file:
        out_file.write("\n".join(summary_lines))

    print(f"✅ Summary written to: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python summarize_snyk_report.py <snyk-report.json>")
        sys.exit(1)

    summarize_vulnerabilities(sys.argv[1])
