import json
import os

def summarize_snyk_report(input_file, output_file):
    if not os.path.exists(input_file):
        with open(output_file, "w") as out:
            out.write("Error: snyk-results.json not found.\n")
        return

    try:
        with open(input_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        with open(output_file, "w") as out:
            out.write("Error: Failed to parse snyk-results.json\n")
        return

    # Handle multiple project results (from --all-projects)
    projects = data.get("runs") if "runs" in data else [data] if isinstance(data, dict) else data

    seen = set()  # To avoid duplicates

    with open(output_file, "w") as out:
        for project in projects:
            vulns = project.get("vulnerabilities", [])
            for vuln in vulns:
                severity = vuln.get("severity", "unknown").upper()
                pkg = vuln.get("package", "unknown")
                version = vuln.get("version", "")
                path = vuln.get("from", ["unknown"])[-1]
                title = vuln.get("title", "No description")
                fixed = vuln.get("fixedIn", [])
                fixed_versions = ", ".join(fixed) if fixed else "Not fixed"

                key = (title, pkg, version)
                if key in seen:
                    continue
                seen.add(key)

                out.write(f"[{severity}] {pkg}@{version} in {path}\n")
                out.write(f"Title: {title}\n")
                out.write(f"Fixed in: {fixed_versions}\n")
                out.write("-" * 50 + "\n")

if __name__ == "__main__":
    summarize_snyk_report("snyk-results.json", "snyk-summary.txt")
