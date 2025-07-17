import json

with open("snyk-results.json", "r") as f:
    data = json.load(f)

summary_lines = []

projects = data.get("runs", [data]) if isinstance(data, dict) else data

for item in projects:
    if "vulnerabilities" not in item:
        continue

    for vuln in item["vulnerabilities"]:
        file = vuln.get("from", ["unknown"])[-1]
        issue = vuln.get("title", "No title")
        severity = vuln.get("severity", "unknown")
        summary_lines.append(f"{severity.upper()} - {file}: {issue}")

with open("snyk-summary.txt", "w") as f:
    f.write("\n".join(summary_lines))

print("Summary written to snyk-summary.txt")
