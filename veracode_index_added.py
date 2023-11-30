import subprocess
import os
import time
import json
import csv
import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout

def extract_report_id(json_response):
    # Parse the JSON response and extract the report ID
    return json.loads(json_response)['_embedded']['id']

def check_report_status(report_id):
    # Veracode API endpoint for getting report status
    api_base = "https://api.veracode.com/appsec/v1"
    report_status_endpoint = f"{api_base}/analytics/report/{report_id}"

    # Send request to Veracode API
    headers = {"User-Agent": "Veracode Report Status Checker"}
    auth = RequestsAuthPluginVeracodeHMAC()
    response = requests.get(report_status_endpoint, auth=auth, headers=headers)

    # Check if the request was successful
    if response.ok:
        data = response.json()
        print("Full Veracode API response:", data)  # Print the entire response for debugging
        return data['_embedded'].get('status')  # Use data['_embedded'].get to handle missing 'status' key
    else:
        response.raise_for_status()

def wait_and_save_output(initial_command, max_poll_attempts=30, poll_interval_seconds=60):
    # Run the initial command to get the report ID
    print("Executing initial command...")
    initial_output = run_command(initial_command)
    print("Initial command executed.")

    # Extract the report ID from the JSON response
    report_id = extract_report_id(initial_output)
    print("Report ID extracted:", report_id)

    # Define the output file name with an index
    output_index = 1
    output_file = f'output_{output_index}.csv'

    # Check if the file already exists and increment the index if needed
    while os.path.exists(output_file):
        output_index += 1
        output_file = f'output_{output_index}.csv'

    # Poll Veracode API to check report status
    for attempt in range(1, max_poll_attempts + 1):
        print(f"Checking Veracode report status. Attempt {attempt}/{max_poll_attempts}...")
        status = check_report_status(report_id)

        if status == "COMPLETED":
            print("Veracode report completed. Fetching the report...")
            get_report_command = f'http --auth-type=veracode_hmac GET "https://api.veracode.com/appsec/v1/analytics/report/{report_id}"'
            output_json = run_command(get_report_command)

            # Parse the JSON output
            output_data = json.loads(output_json)

            # Extract relevant information and save to CSV
            with open(output_file, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                flaws_list = output_data['_embedded']['findings']

                # Check if flaws_list is not empty
                if flaws_list:
                    # Write header
                    csv_writer.writerow(flaws_list[0].keys())

                    # Write data
                    for entry in flaws_list:
                        csv_writer.writerow(entry.values())
                    print("Veracode report saved to", output_file)
                else:
                    print("No flaws found in the Veracode report.")
                break  # Exit the loop since the report has been fetched successfully
        elif status == "PROCESSING":
            # Report is still processing, wait for the next attempt
            time.sleep(poll_interval_seconds)
        else:
            print(f"Unexpected report status: {status}. Exiting.")
            break  # Exit the loop due to unexpected status

# Example usage
initial_command = 'http --auth-type=veracode_hmac POST "https://api.veracode.com/appsec/v1/analytics/report" < finding.json'
wait_and_save_output(initial_command)
