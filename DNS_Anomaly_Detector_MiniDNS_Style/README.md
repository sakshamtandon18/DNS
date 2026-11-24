# DNS Traffic Anomaly Detector — Mini DNS Lookup visual style

Open `index.html` directly in Chrome after extracting the ZIP.

## Included CSV datasets
- `data/normal_dns_traffic.csv`
- `data/suspicious_dns_traffic.csv`
- `data/mixed_dns_traffic.csv`

The sample logs use familiar public domain names (Google, YouTube, GitHub, Wikipedia, Microsoft, Instagram, Amazon and OpenAI) and standard DNS query/response labels. These are illustrative project traffic logs, not captured browsing history or a live scrape of those companies' private DNS traffic. DNS answers can vary by resolver, location and time.

References:
- Google Cloud DNS record types: https://docs.cloud.google.com/dns/docs/records-overview
- Google Public DNS FAQ (including NXDOMAIN): https://developers.google.com/speed/public-dns/faq

CSV columns: `timestamp,domain,query_type,response`.

Features: sample dataset selection, CSV upload, threshold slider, anomaly summary, domain and record tables, and JSON report export.
