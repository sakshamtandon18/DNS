"""Command-line runner: python cli.py data/normal_dns.csv"""
import sys
from detector import load_csv, analyse, save_report

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/normal_dns.csv"
    result = analyse(load_csv(path))
    print("DNS TRAFFIC ANOMALY DETECTOR")
    print("-" * 36)
    for key, value in result["summary"].items():
        print(f"{key.replace('_', ' ').title():24}: {value}")
    print("\nStatus:", result["summary"]["status"])
    if result["errors"]:
        print("\nInput validation messages:")
        for error in result["errors"]:
            print("-", error)
    save_report(result)
    print("\nReport saved to report.json")
