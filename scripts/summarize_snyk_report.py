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

    projects = data if isinstance(data, list) else [data]

    with open(output_file, "w") as out:
        for project in projects:
            if "vulnerabilities" not in project:
                continue

            for vuln in project["vulnerabilities"]:
                severity = vuln.get("severity", "unknown").upper()
                pkg = vuln.get("package", "unknown")
                version = vuln.get("version", "")
                cve = ", ".join(vuln.get("identifiers", {}).get("CVE", []))
                title = vuln.get("title", "No title")
                fixed = vuln.get("fixedIn", []) or vuln.get("upgradePath", [])
                fixed_versions = ", ".join(f for f in fixed if f) if fixed else "Not fixed"

                references = [r.get("url") for r in vuln.get("references", [])]
                ref_str = "\n".join(references)

                description = vuln.get("description", "").split("\n")[0]  # first line

                out.write(f"[{severity}] {pkg}@{version}\n")
                if cve:
                    out.write(f"CVE: {cve}\n")
                out.write(f"Title: {title}\n")
                out.write(f"Description: {description}\n")
                out.write(f"Fixed in: {fixed_versions}\n")
                if references:
                    out.write("References:\n" + ref_str + "\n")
                out.write("-" * 60 + "\n")

if __name__ == "__main__":
    summarize_snyk_report("snyk-results.json", "snyk-summary.txt")
