import json
import re
import subprocess
import zipfile
from pathlib import Path

import requests
from werkzeug.utils import secure_filename

IMAGE_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,199}$")
MAX_DOWNLOAD = 50 * 1024 * 1024      # 50 MB
MAX_UNZIPPED = 300 * 1024 * 1024     # 300 MB

class ScanError(Exception):
    pass

def run_trivy(cmd, out_file):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        raise ScanError("Trivy is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise ScanError("Scan took too long")
    if proc.returncode != 0:
        raise ScanError("Trivy failed: " + proc.stderr[-300:])
    return json.loads(Path(out_file).read_text(encoding="utf-8"))

def scan_image(name, workdir):
    if not IMAGE_PATTERN.match(name):
        raise ScanError("Invalid image name")
    out = Path(workdir) / "result.json"
    cmd = ["trivy", "image", "--scanners", "vuln", "--quiet",
           "--format", "json", "--output", str(out), name]
    return run_trivy(cmd, out)

def scan_tar(path, workdir):
    out = Path(workdir) / "result.json"
    cmd = ["trivy", "image", "--input", str(path), "--scanners", "vuln",
           "--quiet", "--format", "json", "--output", str(out)]
    return run_trivy(cmd, out)

def scan_zip(path, workdir):
    folder = Path(workdir) / "project"
    try:
        with zipfile.ZipFile(path) as z:
            if sum(i.file_size for i in z.infolist()) > MAX_UNZIPPED:
                raise ScanError("Zip is too large when unpacked")
            z.extractall(folder)
    except zipfile.BadZipFile:
        raise ScanError("That is not a valid zip file")
    out = Path(workdir) / "result.json"
    cmd = ["trivy", "fs", "--scanners", "vuln", "--quiet",
           "--format", "json", "--output", str(out), str(folder)]
    return run_trivy(cmd, out)

def download_zip(url, workdir):
    if not url.startswith("https://"):
        raise ScanError("Only https URLs are allowed")
    dest = Path(workdir) / "download.zip"
    size = 0
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(8192):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD:
                        raise ScanError("Download is too large")
                    f.write(chunk)
    except requests.RequestException:
        raise ScanError("Could not download that URL")
    return dest

def save_upload(file, workdir):
    path = Path(workdir) / secure_filename(file.filename)
    file.save(path)
    return path

def detect_input(req):
    if "file" in req.files:
        name = req.files["file"].filename.lower()
        if name.endswith(".tar"):
            return "tar"
        if name.endswith(".zip"):
            return "zip_upload"
        raise ScanError("Upload a .tar or .zip file")
    data = req.get_json(silent=True) or {}
    if data.get("image"):
        return "image"
    if data.get("url"):
        return "zip_url"
    raise ScanError("Send a file, an image name or a zip URL")
