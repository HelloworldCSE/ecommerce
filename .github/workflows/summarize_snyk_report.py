import json
import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any

# Interface for reading reports
class ReportReader(ABC):
    @abstractmethod
    def read(self) -> List[Dict[str, Any]]:
        pass

# Reads and parses a Snyk JSON report
class JSONReportReader(ReportReader):
    def __init__(self, file_path: str):
        self.file_path = file_path

    def read(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        with open(self.file_path, 'r') as f:
            data = json.load(f)

        if "vulnerabilities" in data:
            return data["vulnerabilities"]
        elif "issues" in data and "vulnerabilities" in data["issues"]:
            return data["issues"]["vulnerabilities"]
        elif "runs" in data:
            results = []
            for run in data["runs"]:
                results.extend(run.get("results", []))
            return results
        else:
            return []

# Responsible for formatting the vulnerability output
class VulnerabilityFormatter:
    def format(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        if not vulnerabilities:
            return "No vulnerabilities found."

        output = [f"\nTotal vulnerabilities found: {len(vulnerabilities)}\n"]

        for i, issue in enumerate(vulnerabilities, 1):
            package = issue.get("package", "Not available")
            version = issue.get("version", "Not available")
            severity = issue.get("severity", "Not available")
            title = issue.get("title", issue.get("message", "No title"))
            cwe = issue.get("identifiers", {}).get("CWE", ["Not available"])
            cwe_str = ", ".join(cwe)
            path = " > ".join(issue.get("from", ["Not available"]))

            output.extend([
                f"Vulnerability {i}:",
                f"Package: {package}@{version}",
                f"Path: {path}",
                f"Severity: {severity}",
                f"Title: {title}",
                f"CWE: {cwe_str}",
                "-" * 50
            ])

        return "\n".join(output)

# Summarizer combines reader and formatter
class VulnerabilitySummarizer:
    def __init__(self, reader: ReportReader, formatter: VulnerabilityFormatter):
        self.reader = reader
        self.formatter = formatter

    def summarize(self) -> str:
        vulnerabilities = self.reader.read()
        return self.formatter.format(vulnerabilities)

# Main entry point
if __name__ == "__main__":
    try:
        reader = JSONReportReader("snyk-results.json")
        formatter = VulnerabilityFormatter()
        summarizer = VulnerabilitySummarizer(reader, formatter)

        summary = summarizer.summarize()
        print(summary)

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except json.JSONDecodeError as e:
        print(f"Invalid JSON file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
