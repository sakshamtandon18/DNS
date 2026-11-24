from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from detector import load_csv, analyse, save_report
from pathlib import Path
import io, csv, json

app = Flask(__name__)
app.secret_key = "dns-demo-local-key"
DATA = Path(__file__).parent / "data"
DATA.mkdir(exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    selected = "normal_dns.csv"
    threshold = 0.70
    if request.method == "POST":
        threshold = float(request.form.get("threshold", "0.70"))
        threshold = max(0.10, min(1.0, threshold))
        upload = request.files.get("file")
        if upload and upload.filename:
            try:
                text = upload.stream.read().decode("utf-8-sig")
                rows = list(csv.DictReader(io.StringIO(text)))
                result = analyse(rows, threshold)
                selected = upload.filename
            except Exception as e:
                flash(f"Could not read uploaded CSV: {e}")
        else:
            selected = request.form.get("sample", "normal_dns.csv")
            try:
                result = analyse(load_csv(DATA / selected), threshold)
            except Exception as e:
                flash(f"Could not analyse file: {e}")
    return render_template("index.html", result=result, selected=selected, threshold=threshold)

@app.route("/download-report", methods=["POST"])
def download_report():
    payload = request.form.get("payload", "{}")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {"error": "Report data could not be decoded"}
    raw = json.dumps(data, indent=2).encode()
    return send_file(io.BytesIO(raw), mimetype="application/json",
                     as_attachment=True, download_name="dns_analysis_report.json")

if __name__ == "__main__":
    app.run(debug=True)
