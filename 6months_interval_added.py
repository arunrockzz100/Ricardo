import os
import time
import json
import csv
import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import argparse
from datetime import datetime
from dateutil.relativedelta import relativedelta

def initiate_report(api_base, auth, headers, json_data):
    report_initiate_endpoint = f"{api_base}/analytics/report"
    response = requests.post(report_initiate_endpoint, auth=auth, headers=headers, json=json_data)

    if response.ok:
        data = response.json()
        print("Report initiation successful. Report ID:", data['_embedded']['id'])
        return data['_embedded']['id']
    else:
        response.raise_for_status()

def check_report_status(api_base, auth, report_id):
    report_status_endpoint = f"{api_base}/analytics/report/{report_id}"
    headers = {"User-Agent": "Veracode Report Status Checker"}
    auth = RequestsAuthPluginVeracodeHMAC()
    response = requests.get(report_status_endpoint, auth=auth, headers=headers)

    if response.ok:
        data = response.json()
        print("Full Veracode API response:", data)
        return data['_embedded'].get('status')
    else:
        response.raise_for_status()

def save_report_to_csv(output_file, output_data):
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        flaws_list = output_data['_embedded']['findings']

        if flaws_list:
            csv_writer.writerow(flaws_list[0].keys())
            for entry in flaws_list:
                csv_writer.writerow(entry.values())
            print("Veracode report saved to", output_file)
        else:
            print("No flaws found in the Veracode report.")

def wait_and_save_output(api_base, auth, headers, json_data_template, start_date, num_intervals, max_poll_attempts=30, poll_interval_seconds=60):
    for interval in range(num_intervals):
        json_data = json_data_template.copy()
        json_data["last_updated_start_date"] = start_date
        end_date = datetime.strptime(start_date, "%Y-%m-%d") + relativedelta(months=6)
        json_data["last_updated_end_date"] = end_date.strftime("%Y-%m-%d")

        report_id = initiate_report(api_base, auth, headers, json_data)

        for status_attempt in range(1, max_poll_attempts + 1):
            print(f"Checking Veracode report status. Attempt {status_attempt}/{max_poll_attempts}...")
            status = check_report_status(api_base, auth, report_id)

            if status == "COMPLETED":
                print("Veracode report completed. Fetching the report...")
                get_report_endpoint = f"{api_base}/analytics/report/{report_id}"
                response = requests.get(get_report_endpoint, auth=auth, headers=headers)
                output_data = response.json()

                output_file = f'output_{interval + 1}.csv'
                save_report_to_csv(output_file, output_data)

                # Move on to the next interval
                start_date = end_date.strftime("%Y-%m-%d")
                break

            elif status == "PROCESSING":
                time.sleep(poll_interval_seconds)

            else:
                print(f"Unexpected report status: {status}. Exiting.")
                return

def parse_arguments():
    parser = argparse.ArgumentParser(description="Veracode Report Script")
    parser.add_argument("--start-date", required=True, help="Start date for the first report in the format 'YYYY-MM-DD'")
    parser.add_argument("--num-intervals", type=int, required=True, help="Number of 6-month intervals")
    return parser.parse_args()

args = parse_arguments()
start_date = args.start_date
num_intervals = args.num_intervals

json_data_template = {
    "scan_type": ["Static Analysis", "Dynamic Analysis", "Manual Analysis", "SCA"],
    "policy_sandbox": "Policy",
    "status": "open",
    "report_type": "findings",
    "last_updated_start_date": "",
    "last_updated_end_date": ""
}

api_base = "https://api.veracode.com/appsec/v1"
auth = RequestsAuthPluginVeracodeHMAC()
headers = {"User-Agent": "Veracode Report Script"}

wait_and_save_output(api_base, auth, headers, json_data_template, start_date, num_intervals)
