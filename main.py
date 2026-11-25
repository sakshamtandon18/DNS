# DNS Traffic Anomaly Detector
# Beginner-friendly Python project
# Run: python main.py
# Run with another CSV file: python main.py your_file.csv

import csv
import sys
from collections import Counter


def load_dns_data(filename):
    """Read DNS records from a CSV file."""
    records = []

    try:
        with open(filename, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                records.append(row)
    except FileNotFoundError:
        print("Error: File not found:", filename)
    except Exception as error:
        print("Error reading file:", error)

    return records


def detect_anomaly(record, queries_from_ip):
    """Apply a few simple rules to identify unusual DNS records."""
    reasons = []
    domain = record["domain"].strip()
    response = record.get("response_code", "").strip().upper()

    if queries_from_ip > 5:
        reasons.append("High number of DNS queries from this IP")

    if len(domain) > 50:
        reasons.append("Unusually long domain name")

    if domain.count(".") > 5:
        reasons.append("Too many subdomains")

    if response == "NXDOMAIN":
        reasons.append("Requested domain does not exist")

    if reasons:
        return "ANOMALY", ", ".join(reasons)

    return "NORMAL", "No suspicious activity detected"


def analyse_records(records):
    """Count requests from each IP and analyse every record."""
    ip_counts = Counter()

    for record in records:
        ip = record.get("src_ip", "").strip()
        if ip:
            ip_counts[ip] += 1

    results = []

    for record in records:
        # Skip incomplete rows
        if not record.get("src_ip") or not record.get("domain") or not record.get("query_type"):
            print("Skipping an incomplete CSV row:", record)
            continue

        ip = record["src_ip"].strip()
        status, reason = detect_anomaly(record, ip_counts[ip])

        results.append({
            "timestamp": record.get("timestamp", ""),
            "src_ip": ip,
            "domain": record["domain"].strip(),
            "query_type": record["query_type"].strip().upper(),
            "response_code": record.get("response_code", "").strip().upper(),
            "status": status,
            "reason": reason
        })

    return results


def show_results(results):
    """Display a readable report on the screen."""
    print("\n========== DNS TRAFFIC ANALYSIS ==========")

    if not results:
        print("No DNS records were available to analyse.")
        return

    normal_count = 0
    anomaly_count = 0

    for item in results:
        print("\nTime:", item["timestamp"])
        print("Source IP:", item["src_ip"])
        print("Domain:", item["domain"])
        print("Query type:", item["query_type"])
        print("Result:", item["status"])
        print("Reason:", item["reason"])

        if item["status"] == "ANOMALY":
            anomaly_count += 1
        else:
            normal_count += 1

    print("\n--------------- SUMMARY -----------------")
    print("Total records:", len(results))
    print("Normal records:", normal_count)
    print("Anomalies detected:", anomaly_count)


def save_report(results):
    """Save the analysis results to a new CSV report."""
    output_file = "dns_report.csv"
    columns = [
        "timestamp", "src_ip", "domain", "query_type",
        "response_code", "status", "reason"
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(results)

    print("\nReport saved as:", output_file)


def main():
    # Use the filename supplied by the user, or the sample file by default.
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "dns_data.csv"

    print("DNS Traffic Anomaly Detection")
    print("Reading data from:", filename)

    records = load_dns_data(filename)
    results = analyse_records(records)

    show_results(results)

    if results:
        save_report(results)

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()
