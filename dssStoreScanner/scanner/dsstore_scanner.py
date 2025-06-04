
import os
import subprocess
import requests
import argparse
import threading
from urllib.parse import urljoin, urlparse
from datetime import datetime

SENSITIVE_KEYWORDS = ['.git', '.env', 'config.php', 'backup', 'db.sql', '.bak', '.zip', '.tar', '.rar']

parser = argparse.ArgumentParser(description=".DS_Store Vulnerability Scanner with Parallel Threading")
parser.add_argument("-u", "--url", help="Single .DS_Store URL to scan")
parser.add_argument("-i", "--input", help="File with list of .DS_Store URLs to scan (one per line)")
parser.add_argument("--threads", type=int, default=5, help="Number of parallel threads (default: 5)")
args = parser.parse_args()

if not args.url and not args.input:
    parser.error("You must provide either -u <url> or -i <input_file>")

DSSTORE_PARSER = "dsstore/dsstore.py"
TIMEOUT = 10
os.makedirs("dsstore_scan_results", exist_ok=True)

def is_sensitive(path):
    return any(keyword in path.lower() for keyword in SENSITIVE_KEYWORDS)

def download_dsstore(target_url, save_path):
    try:
        r = requests.get(target_url, timeout=TIMEOUT)
        if r.status_code != 200:
            print(f"[-] {target_url} returned HTTP {r.status_code}")
            return False
        with open(save_path, "wb") as f:
            f.write(r.content)
        return True
    except Exception as e:
        print(f"[-] Failed to download from {target_url}: {e}")
        return False

def parse_dsstore(dsstore_path):
    try:
        result = subprocess.run(
            ["python3", DSSTORE_PARSER, dsstore_path],
            capture_output=True,
            text=True
        )
        return result.stdout.strip().splitlines()
    except Exception as e:
        print(f"[-] Error parsing .DS_Store: {e}")
        return []

def check_paths(base_url, paths):
    checked = []
    for path in paths:
        test_url = urljoin(base_url, path)
        try:
            r = requests.head(test_url, timeout=TIMEOUT, allow_redirects=True)
            status = r.status_code
        except:
            status = "error"
        checked.append((path, status))
    return checked

def make_report(domain, base_url, results):
    safe_domain = domain.replace("https://", "").replace("http://", "").replace("/", "_")
    report_path = f"dsstore_scan_results/{safe_domain}.html"
    with open(report_path, "w") as f:
        f.write("<html><head><title>.DS_Store Report</title></head><body>")
        f.write(f"<h2>.DS_Store Report for {domain}</h2>")
        f.write(f"<p>Scanned URL: {base_url}</p>")
        f.write("<table border='1' cellpadding='5'><tr><th>Path</th><th>Status</th><th>Link</th><th>Flag</th></tr>")
        for path, status in results:
            full_url = urljoin(base_url, path)
            color = "red" if status == 200 else "orange" if status == 403 else "gray"
            flag = "🔴 <b>SENSITIVE</b>" if is_sensitive(path) else ""
            f.write(f"<tr><td>{path}</td><td style='color:{color}'>{status}</td><td><a href='{full_url}' target='_blank'>Open</a></td><td>{flag}</td></tr>")
        f.write("</table></body></html>")
    print(f"[✓] Report saved to {report_path}")

def scan_dsstore(target_url):
    parsed = urlparse(target_url)
    domain = f"{parsed.scheme}://{parsed.netloc}/"
    print(f"\n[+] Scanning: {target_url}")
    if not download_dsstore(target_url, "temp_dsstore"):
        return
    paths = parse_dsstore("temp_dsstore")
    print(f"[+] Found {len(paths)} paths")
    results = check_paths(target_url, paths)
    make_report(domain, target_url, results)

def threaded_scan(urls, thread_count):
    def worker():
        while True:
            try:
                url = url_queue.pop()
            except IndexError:
                break
            scan_dsstore(url)

    url_queue = list(urls)
    threads = []
    for _ in range(min(thread_count, len(url_queue))):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

if args.url:
    scan_dsstore(args.url)

if args.input:
    with open(args.input, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        threaded_scan(urls, args.threads)

print("\n[✓] All scans completed.")
