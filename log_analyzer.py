#!/usr/bin/env python3
"""
SSH Brute-force & Anomaly Detector for auth.log
Generates HTML report, CSV export, Telegram alert and optional DeepSeek interpretation.
"""

import re
import csv
import argparse
import base64
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from io import BytesIO, StringIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import requests

# Optional GeoIP support
try:
    import maxminddb
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# ------------------------------------------------------------------------------
# Configuration & constants
# ------------------------------------------------------------------------------
FAILED_PATTERN = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
TIMESTAMP_FORMAT = "%b %d %H:%M:%S"  # syslog default (without year)

# Default thresholds
DEFAULT_WINDOW_MIN = 5          # sliding window in minutes
DEFAULT_BRUTEFORCE_THRESH = 5   # failed attempts per window per IP
DEFAULT_USER_SCAN_THRESH = 5    # distinct usernames per IP

# ------------------------------------------------------------------------------
# Log parsing
# ------------------------------------------------------------------------------
def parse_auth_log(log_path: str, year: int = None) -> list:
    """
    Read auth.log and return list of (datetime, user, ip) for failed SSH attempts.
    If year is not provided, use current year for timestamps that lack it.
    """
    if not year:
        year = datetime.now().year

    entries = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_PATTERN.search(line)
            if not match:
                continue
            try:
                ts_str = f"{year} " + match.group("timestamp")
                dt = datetime.strptime(ts_str, f"%Y {TIMESTAMP_FORMAT}")
            except ValueError:
                continue
            entries.append((dt, match.group("user"), match.group("ip")))
    return entries

# ------------------------------------------------------------------------------
# Detection logic
# ------------------------------------------------------------------------------
def detect_bruteforce(entries, window_minutes=5, threshold=5):
    """
    Sliding window brute-force detection.
    Returns list of (ip, start_time, end_time, count) for IPs exceeding threshold.
    """
    if not entries:
        return []

    # Sort by time
    sorted_entries = sorted(entries, key=lambda x: x[0])
    window = timedelta(minutes=window_minutes)
    attacks = []
    i = 0
    while i < len(sorted_entries):
        start = sorted_entries[i][0]
        end_time = start + window
        # find all attempts within window for the same IP
        ip = sorted_entries[i][2]
        count = 0
        j = i
        while j < len(sorted_entries) and sorted_entries[j][0] <= end_time:
            if sorted_entries[j][2] == ip:
                count += 1
            j += 1
        if count >= threshold:
            # Record attack
            attacks.append((ip, start, end_time, count))
            # Skip all processed entries for this IP within the window
            i = j
        else:
            i += 1
    return attacks

def detect_user_scanning(entries, threshold=5):
    """
    Detect IPs that tried many distinct usernames (possible user enumeration).
    Returns dict {ip: set_of_users} for IPs with >= threshold distinct users.
    """
    ip_users = defaultdict(set)
    for dt, user, ip in entries:
        ip_users[ip].add(user)
    return {ip: users for ip, users in ip_users.items() if len(users) >= threshold}

# ------------------------------------------------------------------------------
# Report generation
# ------------------------------------------------------------------------------
def generate_html_report(entries, bruteforce_attacks, user_scanners, geoip_db=None):
    """Create HTML report with summary, tables and embedded charts."""
    # Prepare data for charts
    ip_counts = Counter(ip for _, _, ip in entries)
    top_ips = ip_counts.most_common(10)

    # Time series: group attempts by minute
    time_series = defaultdict(int)
    for dt, _, _ in entries:
        minute = dt.replace(second=0, microsecond=0)
        time_series[minute] += 1
    minutes = sorted(time_series.keys())
    counts = [time_series[m] for m in minutes]

    # Chart 1: attempts over time
    plt.figure(figsize=(10, 4))
    plt.plot(minutes, counts, marker='.', linestyle='-', color='navy')
    plt.title("SSH Failed Attempts Timeline")
    plt.xlabel("Time")
    plt.ylabel("Attempts per minute")
    plt.xticks(rotation=45)
    plt.tight_layout()
    buf1 = BytesIO()
    plt.savefig(buf1, format='png', dpi=100)
    buf1.seek(0)
    chart1_b64 = base64.b64encode(buf1.read()).decode()
    plt.close()

    # Chart 2: top attacking IPs
    plt.figure(figsize=(8, 4))
    labels = [ip for ip, _ in top_ips]
    values = [cnt for _, cnt in top_ips]
    plt.barh(labels, values, color='firebrick')
    plt.title("Top 10 IPs by Failed Attempts")
    plt.xlabel("Attempts")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    buf2 = BytesIO()
    plt.savefig(buf2, format='png', dpi=100)
    buf2.seek(0)
    chart2_b64 = base64.b64encode(buf2.read()).decode()
    plt.close()

    # Country data (if GeoIP available)
    country_data = {}
    if geoip_db and GEOIP_AVAILABLE:
        for ip in ip_counts:
            try:
                response = geoip_db.get(ip)
                country = response.get("country", {}).get("names", {}).get("en", "Unknown")
                country_data[ip] = country
            except Exception:
                country_data[ip] = "Unknown"

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>SSH Log Analysis Report</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    h1, h2 {{ color: #333; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background-color: #f2f2f2; }}
    .alert {{ background-color: #ffe6e6; }}
</style>
</head>
<body>
<h1>🔒 SSH Log Analysis Report</h1>
<p>Generated at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

<h2>Summary</h2>
<ul>
    <li>Total failed attempts: {len(entries)}</li>
    <li>Unique IPs: {len(ip_counts)}</li>
    <li>Brute-force attacks detected: {len(bruteforce_attacks)}</li>
    <li>User scanners detected: {len(user_scanners)}</li>
</ul>

<h2>Timeline of Failed Attempts</h2>
<img src="data:image/png;base64,{chart1_b64}" alt="Timeline" style="max-width:100%;">

<h2>Top Attacking IPs</h2>
<img src="data:image/png;base64,{chart2_b64}" alt="Top IPs" style="max-width:100%;">

<h2>Brute-Force Attacks (window={DEFAULT_WINDOW_MIN} min, threshold={DEFAULT_BRUTEFORCE_THRESH})</h2>
<table>
<tr><th>IP</th><th>Country</th><th>Start</th><th>End</th><th>Attempts</th></tr>
"""
    for ip, start, end, cnt in bruteforce_attacks:
        country = country_data.get(ip, "N/A")
        html += f"<tr class='alert'><td>{ip}</td><td>{country}</td><td>{start}</td><td>{end}</td><td>{cnt}</td></tr>\n"

    html += """</table>

<h2>User Scanning (threshold >= {thresh} distinct usernames)</h2>
<table>
<tr><th>IP</th><th>Country</th><th>Distinct Users</th><th>List</th></tr>
""".format(thresh=DEFAULT_USER_SCAN_THRESH)
    for ip, users in user_scanners.items():
        country = country_data.get(ip, "N/A")
        html += f"<tr class='alert'><td>{ip}</td><td>{country}</td><td>{len(users)}</td><td>{', '.join(sorted(users))}</td></tr>\n"

    html += """</table>
</body>
</html>"""
    return html

def save_csv(entries, filename="failed_attempts.csv"):
    """Save all parsed entries to CSV."""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "username", "ip"])
        for dt, user, ip in entries:
            writer.writerow([dt.isoformat(), user, ip])
    return filename
  # ------------------------------------------------------------------------------
# Telegram alerting
# ------------------------------------------------------------------------------
def send_telegram_alert(html_report: str, token: str, chat_id: str, summary_text: str = None):
    """
    Send a text summary and the HTML report (as a .html file) to a Telegram chat.
    """
    if not token or not chat_id:
        logging.warning("Telegram token/chat_id not provided. Skipping alert.")
        return

    base_url = f"https://api.telegram.org/bot{token}"

    # Send summary text
    if summary_text:
        requests.post(f"{base_url}/sendMessage", json={
            "chat_id": chat_id,
            "text": summary_text,
            "parse_mode": "Markdown"
        })

    # Send HTML file as document
    try:
        with BytesIO(html_report.encode("utf-8")) as f:
            f.name = "ssh_report.html"
            requests.post(f"{base_url}/sendDocument", files={"document": f}, data={"chat_id": chat_id})
    except Exception as e:
        logging.error(f"Failed to send Telegram document: {e}")

# ------------------------------------------------------------------------------
# DeepSeek interpretation (optional)
# ------------------------------------------------------------------------------
def analyze_with_deepseek(entries: list, api_key: str, endpoint: str = "https://api.deepseek.com/chat/completions",
                          model: str = "deepseek-chat") -> str:
    """
    Send a summary of detected attacks to DeepSeek and return an interpretation.
    Requires DEEPSEEK_API_KEY environment variable or passed directly.
    """
    if not api_key:
        return "[DeepSeek not configured]"

    # Prepare a brief summary of the log
    total_attempts = len(entries)
    unique_ips = len(Counter(ip for _, _, ip in entries))
    top_ips = Counter(ip for _, _, ip in entries).most_common(5)
    top_users = Counter(user for _, user, _ in entries).most_common(5)

    summary_lines = [
        f"Total failed SSH attempts: {total_attempts}",
        f"Unique source IPs: {unique_ips}",
        "Top 5 attacking IPs:",
    ]
    for ip, cnt in top_ips:
        summary_lines.append(f"  {ip}: {cnt}")
    summary_lines.append("Most targeted usernames:")
    for user, cnt in top_users:
        summary_lines.append(f"  {user}: {cnt}")

    prompt = (
        "You are a SOC analyst assistant. Analyze the following SSH log summary and provide a concise "
        "explanation of what kind of attacks are likely occurring (brute-force, user enumeration, etc.) "
        "and any recommended mitigation.\n\n"
        + "\n".join(summary_lines)
    )

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 300
    }

    try:
        resp = requests.post(endpoint, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error(f"DeepSeek API error: {e}")
        return f"[DeepSeek error: {e}]"

# ------------------------------------------------------------------------------
# Main CLI
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SSH Log Analyzer - detects brute-force, user scanning and more.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python log_analyzer.py /var/log/auth.log --telegram-token XXX --telegram-chat-id YYY"
    )
    parser.add_argument("logfile", help="Path to auth.log or similar syslog file")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_MIN,
                        help=f"Sliding window in minutes (default: {DEFAULT_WINDOW_MIN})")
    parser.add_argument("--bf-threshold", type=int, default=DEFAULT_BRUTEFORCE_THRESH,
                        help=f"Brute-force attempt threshold per window (default: {DEFAULT_BRUTEFORCE_THRESH})")
    parser.add_argument("--user-scan-threshold", type=int, default=DEFAULT_USER_SCAN_THRESH,
                        help=f"Distinct usernames threshold for scanning (default: {DEFAULT_USER_SCAN_THRESH})")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="Year for timestamps that lack it (default: current year)")
    parser.add_argument("--output-html", default="ssh_report.html",
                        help="Output HTML report file (default: ssh_report.html)")
    parser.add_argument("--output-csv", default="failed_attempts.csv",
                        help="Output CSV file (default: failed_attempts.csv)")
    parser.add_argument("--telegram-token", help="Telegram Bot API token")
    parser.add_argument("--telegram-chat-id", help="Telegram chat ID to send report")
    parser.add_argument("--deepseek-api-key", help="DeepSeek API key for AI interpretation")
    parser.add_argument("--geoip-db", help="Path to GeoLite2-Country.mmdb for IP geolocation")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")

    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s")

    # 1. Parse log
    entries = parse_auth_log(args.logfile, args.year)
    if not entries:
        logging.info("No failed SSH attempts found.")
        return

    logging.info(f"Parsed {len(entries)} failed attempts.")

    # 2. Detect threats
    bf_attacks = detect_bruteforce(entries, args.window, args.bf_threshold)
    user_scanners = detect_user_scanning(entries, args.user_scan_threshold)

    logging.info(f"Detected {len(bf_attacks)} brute-force events and {len(user_scanners)} user scanners.")

    # 3. Optional GeoIP
    geoip_db = None
    if args.geoip_db and GEOIP_AVAILABLE:
        try:
            geoip_db = maxminddb.open_database(args.geoip_db)
        except Exception as e:
            logging.error(f"Failed to open GeoIP database: {e}")

    # 4. Generate HTML report
    html = generate_html_report(entries, bf_attacks, user_scanners, geoip_db)
    with open(args.output_html, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"HTML report saved to {args.output_html}")

    # 5. Save CSV
    save_csv(entries, args.output_csv)
    logging.info(f"CSV saved to {args.output_csv}")

    # 6. Optional DeepSeek AI interpretation
    deepseek_insight = ""
    if args.deepseek_api_key:
        deepseek_insight = analyze_with_deepseek(entries, args.deepseek_api_key)
        logging.info("DeepSeek analysis complete.")
        if not args.quiet:
            print("\n--- DeepSeek Interpretation ---")
            print(deepseek_insight)

    # 7. Telegram alert
    if args.telegram_token and args.telegram_chat_id:
        total_attempts = len(entries)
        uniq_ips = len(Counter(ip for _, _, ip in entries))
        summary = (
            f"🔒 *SSH Log Analysis*\n"
            f"• Total failed attempts: {total_attempts}\n"
            f"• Unique IPs: {uniq_ips}\n"
            f"• Brute‑force attacks: {len(bf_attacks)}\n"
            f"• User scanners: {len(user_scanners)}"
        )
        if deepseek_insight:
            summary += f"\n\n🤖 *AI Insight*:\n{deepseek_insight[:400]}..."

        send_telegram_alert(html, args.telegram_token, args.telegram_chat_id, summary)
        logging.info("Telegram alert sent.")

    if geoip_db:
        geoip_db.close()

    # Print quick summary to stdout unless quiet
    if not args.quiet:
        print(f"\n=== Analysis complete ===")
        print(f"Total attempts: {len(entries)}")
        print(f"Brute-force IPs: {len(bf_attacks)}")
        print(f"User scanners: {len(user_scanners)}")
        print(f"Reports: {args.output_html}, {args.output_csv}")

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
