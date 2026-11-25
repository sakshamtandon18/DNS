DNS TRAFFIC ANOMALY DETECTOR
=============================

FILES
-----
main.py       Main Python program
dns_data.csv  Sample DNS traffic data

REQUIREMENTS
------------
- Python 3
- No extra libraries are needed. The project uses Python built-in libraries only.

HOW TO RUN
----------
1. Keep main.py and dns_data.csv in the same folder.
2. Open a terminal or command prompt in that folder.
3. Run:

       python main.py

4. The program analyses the sample data and displays NORMAL or ANOMALY.
5. It also creates dns_report.csv containing the results.

USE YOUR OWN CSV FILE
---------------------
Your CSV file should have these column headings:

timestamp,src_ip,domain,query_type,response_code

Run it with:

       python main.py your_file.csv

HOW DETECTION WORKS
-------------------
The program marks a record as ANOMALY if one or more of these simple
conditions are true:
- More than 5 DNS records came from the same source IP in the input file.
- The domain name is longer than 50 characters.
- The domain contains more than 5 dots (many subdomain levels).
- The DNS response code is NXDOMAIN.

Otherwise, the record is marked NORMAL.

IMPORTANT
---------
This is a beginner-friendly, rule-based demonstration using sample CSV data.
An ANOMALY label is only an indicator for review; it does not prove that
an attack has occurred. The query-count rule counts records in the entire
input file, not within a timed window.
