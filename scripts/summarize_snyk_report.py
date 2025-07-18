import json
import os
import sys
import traceback
from datetime import datetime

def main():
    """Main function with enhanced error handling"""
    try:
        print("Starting Snyk summary generation...")
        
        # Ensure scripts directory exists
        os.makedirs('scripts', exist_ok=True)
        print("Scripts directory ensured")
        
        json_data = None
        
        # Read from command line argument
        if len(sys.argv) > 1:
            file_path = sys.argv[1]
            print(f"Reading Snyk data from file: {file_path}")
            
            if not os.path.exists(file_path):
                print(f"ERROR: File not found: {file_path}")
                create_error_summary(f"Input file not found: {file_path}")
                return
            
            try:
                with open(file_path, 'r') as f:
                    json_data = f.read()
                print(f"Successfully read {len(json_data)} characters from file")
            except Exception as e:
                print(f"ERROR: Failed to read file: {e}")
                create_error_summary(f"Failed to read file: {e}")
                return
        else:
            print("ERROR: No input file provided")
            create_error_summary("No input file provided")
            return
        
        # Validate JSON data
        if not json_data or json_data.strip() == "":
            print("ERROR: Empty JSON data")
            create_error_summary("Empty JSON data received")
            return
        
        # Parse JSON
        try:
            parsed_results = parse_snyk_json(json_data)
            print(f"Successfully parsed {len(parsed_results)} projects")
        except Exception as e:
            print(f"ERROR: JSON parsing failed: {e}")
            create_error_summary(f"JSON parsing failed: {e}")
            return
        
        # Generate summary
        try:
            summary = generate_summary(parsed_results)
            print("Summary generated successfully")
        except Exception as e:
            print(f"ERROR: Summary generation failed: {e}")
            create_error_summary(f"Summary generation failed: {e}")
            return
        
        # Write summary file
        try:
            with open('scripts/snyk-summary.txt', 'w') as f:
                f.write(summary)
            print("Summary file written successfully")
        except Exception as e:
            print(f"ERROR: Failed to write summary file: {e}")
            create_error_summary(f"Failed to write summary file: {e}")
            return
        
        # Success message
        total_vulns = sum(p['total_vulnerabilities'] for p in parsed_results)
        print(f"SUCCESS: Summary generated with {total_vulns} vulnerabilities across {len(parsed_results)} projects")
        
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        print("Traceback:")
        traceback.print_exc()
        create_error_summary(f"Critical error: {e}")

def create_error_summary(error_message):
    """Create an error summary file"""
    try:
        os.makedirs('scripts', exist_ok=True)
        with open('scripts/snyk-summary.txt', 'w') as f:
            f.write("# Snyk Vulnerability Scan Summary\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("## Error Status\n")
            f.write(f"**Error:** {error_message}\n\n")
            f.write("## Troubleshooting\n")
            f.write("1. Check Snyk authentication token\n")
            f.write("2. Verify project contains scannable files\n")
            f
