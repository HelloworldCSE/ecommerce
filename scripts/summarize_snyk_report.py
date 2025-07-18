import json
import os
import sys
from datetime import datetime

def parse_snyk_json(json_data):
    """Parse Snyk JSON data and extract key information"""
    try:
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data

        # Handle different Snyk output formats
        if isinstance(data, list):
            # Multiple projects
            results = []
            for project in data:
                results.append(parse_single_project(project))
            return results
        else:
            # Single project
            return [parse_single_project(data)]
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return []

def parse_single_project(project_data):
    """Parse a single project's Snyk results"""
    result = {
        'project_name': project_data.get('projectName', 'Unknown'),
        'package_manager': project_data.get('packageManager', 'Unknown'),
        'vulnerabilities': project_data.get('vulnerabilities', []),
        'total_vulnerabilities': len(project_data.get('vulnerabilities', [])),
        'severity_counts': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }

    # Count vulnerabilities by severity
    for vuln in result['vulnerabilities']:
        severity = vuln.get('severity', 'unknown').lower()
        if severity in result['severity_counts']:
            result['severity_counts'][severity] += 1

    return result

def generate_summary(parsed_results):
    """Generate human-readable summary"""
    summary_lines = []
    summary_lines.append("# Snyk Vulnerability Scan Summary")
    summary_lines.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_lines.append("")

    total_vulnerabilities = 0
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0

    for project in parsed_results:
        total_vulnerabilities += project['total_vulnerabilities']
        total_critical += project['severity_counts']['critical']
        total_high += project['severity_counts']['high']
        total_medium += project['severity_counts']['medium']
        total_low += project['severity_counts']['low']

        summary_lines.append(f"## Project: {project['project_name']}")
        summary_lines.append(f"Package Manager: {project['package_manager']}")
        summary_lines.append(f"Total Vulnerabilities: {project['total_vulnerabilities']}")
        summary_lines.append("")

        if project['total_vulnerabilities'] > 0:
            summary_lines.append("### Severity Breakdown:")
            summary_lines.append(f"- Critical: {project['severity_counts']['critical']}")
            summary_lines.append(f"- High: {project['severity_counts']['high']}")
            summary_lines.append(f"- Medium: {project['severity_counts']['medium']}")
            summary_lines.append(f"- Low: {project['severity_counts']['low']}")
            summary_lines.append("")

            # Top 5 most severe vulnerabilities
            sorted_vulns = sorted(
                project['vulnerabilities'],
                key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x.get('severity', 'low').lower(), 0),
                reverse=True
            )[:5]

            if sorted_vulns:
                summary_lines.append("### Top 5 Most Severe Vulnerabilities:")
                for i, vuln in enumerate(sorted_vulns, 1):
                    title = vuln.get('title', 'Unknown vulnerability')
                    severity = vuln.get('severity', 'Unknown')
                    package_name = vuln.get('packageName', 'Unknown package')
                    summary_lines.append(f"{i}. **{title}** (Severity: {severity})")
                    summary_lines.append(f"   Package: {package_name}")
                    summary_lines.append("")
        else:
            summary_lines.append(" No vulnerabilities found in this project!")
            summary_lines.append("")

    # Overall summary
    summary_lines.append("## Overall Summary")
    summary_lines.append(f"Total Projects Scanned: {len(parsed_results)}")
    summary_lines.append(f"Total Vulnerabilities: {total_vulnerabilities}")
    summary_lines.append("")

    if total_vulnerabilities > 0:
        summary_lines.append("### Overall Severity Distribution:")
        summary_lines.append(f"- Critical: {total_critical}")
        summary_lines.append(f"- High: {total_high}")
        summary_lines.append(f"- Medium: {total_medium}")
        summary_lines.append(f"- Low: {total_low}")
        summary_lines.append("")

        # Risk assessment
        if total_critical > 0:
            summary_lines.append(" **IMMEDIATE ACTION REQUIRED**: Critical vulnerabilities detected!")
        elif total_high > 0:
            summary_lines.append("  **HIGH PRIORITY**: High severity vulnerabilities need attention.")
        elif total_medium > 0:
            summary_lines.append(" **MEDIUM PRIORITY**: Medium severity vulnerabilities should be addressed.")
        else:
            summary_lines.append(" **LOW RISK**: Only low severity vulnerabilities found.")
    else:
        summary_lines.append(" **EXCELLENT**: No vulnerabilities detected across all projects!")

    return "\n".join(summary_lines)

def main():
    """Main function to process Snyk JSON data and generate summary"""
    try:
        # Method 1: Read from environment variable (preferred)
        json_data = os.environ.get('SNYK_JSON_DATA')

        if json_data:
            print("Reading Snyk data from environment variable...")
            parsed_results = parse_snyk_json(json_data)
        else:
            # Fallback: Read from file if environment variable not available
            print("Environment variable not found, trying to read from file...")
            try:
                with open('snyk-results.json', 'r') as f:
                    json_data = f.read()
                parsed_results = parse_snyk_json(json_data)
            except FileNotFoundError:
                print("No Snyk results found. Please run Snyk scan first.")
                return

        # Generate summary
        summary = generate_summary(parsed_results)

        # Write summary to file
        with open('snyk-summary.txt', 'w') as f:
            f.write(summary)

        print("Summary generated successfully!")
        print("\n" + "="*50)
        print(summary)
        print("="*50)

    except Exception as e:
        print(f"Error generating summary: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
