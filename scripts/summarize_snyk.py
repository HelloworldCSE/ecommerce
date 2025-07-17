import json
import os

def summarize_snyk_report(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        with open(output_file, "w") as out:
            out.write("Error: Failed to parse snyk-results.json\n")
        return

    projects = data if isinstance(data, list) else [data]

    with open(output_file, "w") as out:
        for project in projects:
            if "vulnerabilities" not in project:
                continue
            for vuln in project["vulnerabilities"]:
                severity = vuln.get("severity", "unknown").upper()
                pkg = vuln.get("package", "unknown")
                version = vuln.get("version", "")
                path = vuln.get("from", [])[0] if vuln.get("from") else "unknown"
                title = vuln.get("title", "No description")
                fixed = vuln.get("fixedIn", [])
                fixed_versions = ", ".join(fixed) if fixed else "Not fixed"

                out.write(f"[{severity}] {pkg}@{version} in {path}\n")
                out.write(f"Title: {title}\n")
                out.write(f"Fixed in: {fixed_versions}\n")
                out.write("-" * 50 + "\n")

if __name__ == "__main__":
    summarize_snyk_report("snyk-results.json", "snyk-summary.txt")
