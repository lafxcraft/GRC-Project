import tempfile
from flask import Flask, jsonify, request
from scanner import (ScanError, detect_input, scan_image, scan_tar,
                     scan_zip, download_zip, save_upload)
from scoring import parse_trivy

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024   # 500 MB

def field(name, default=None):
    if request.is_json:
        return (request.get_json() or {}).get(name, default)
    return request.form.get(name, default)

@app.route("/")
def home():
    return app.send_static_file("index.html")

@app.errorhandler(413)
def too_big(err):
    return jsonify({"error": "File is too large"}), 413

@app.route("/api/scan", methods=["POST"])
def scan():
    try:
        kind = detect_input(request)
        criticality = int(field("criticality", 4))
        if not 1 <= criticality <= 5:
            raise ScanError("Criticality must be 1 to 5")
        with tempfile.TemporaryDirectory() as workdir:
            if kind == "image":
                data = scan_image(field("image"), workdir)
            elif kind == "tar":
                data = scan_tar(save_upload(request.files["file"], workdir), workdir)
            elif kind == "zip_upload":
                data = scan_zip(save_upload(request.files["file"], workdir), workdir)
            else:
                data = scan_zip(download_zip(field("url"), workdir), workdir)
    except (ScanError, ValueError) as err:
        return jsonify({"error": str(err)}), 400
    rows = parse_trivy(data, criticality)
    levels = ["Critical", "High", "Medium", "Low"]
    summary = {lv: sum(1 for r in rows if r["level"] == lv) for lv in levels}
    return jsonify({"kind": kind, "summary": summary, "findings": rows})

if __name__ == "__main__":
    app.run(port=5000)
