#!/usr/bin/env python3

import email
from email import policy
from email.parser import BytesParser
import argparse
import hashlib
import json
import os
import re
import time
import socket
import requests
from colorama import Fore, Style, init

init(autoreset=True)

# =============================
# TOOL INFO
# =============================
AUTHOR = "Sushil Maurya"
TOOL_NAME = "Smells Good Email Security Analyzer"
VERSION = "v1.2"

VT_API_KEY = "PUT_YOUR_VT_API_KEY_HERE"

# =============================
# ASCII BANNERS
# =============================

def smells_good_banner():
    print(Fore.GREEN + f"""
 ███████╗███╗   ███╗███████╗██╗     ██╗     ███████╗
 ██╔════╝████╗ ████║██╔════╝██║     ██║     ██╔════╝
 ███████╗██╔████╔██║█████╗  ██║     ██║     ███████╗
 ╚════██║██║╚██╔╝██║██╔══╝  ██║     ██║     ╚════██║
 ███████║██║ ╚═╝ ██║███████╗███████╗███████╗███████║
 ╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝

             G   O   O   D

        {Style.BRIGHT}{TOOL_NAME} {VERSION}
        Author : {AUTHOR}
        SOC | Phishing | Malware Analysis
 -----------------------------------------------------
""")

def phishing_banner():
    print(Fore.CYAN + r"""
            ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
            ~      suspicious waters     ~
            ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~

                  O
                 /|\
                 / \          🎣
              SOC ANALYST ------|
                    \
                     \_____[ PHISH ]

        "If it SMELLS GOOD… it's probably PHISHING."
""")

# =============================
# LOADING ANIMATION
# =============================

def loading_step(message, delay=0.3, dots=3):
    print(Fore.GREEN + f"[*] {message}", end="")
    for _ in range(dots):
        time.sleep(delay)
        print(".", end="")
    print()

def loading_animation():
    loading_step("Initializing analyzer")
    loading_step("Parsing email headers")
    loading_step("Extracting URLs and content")
    loading_step("Scanning URLs with VirusTotal")
    loading_step("Analyzing authentication results")
    loading_step("Calculating risk score")
    loading_step("Finalizing report")
    print()

# =============================
# HELPERS
# =============================

def sha256_file(data):
    return hashlib.sha256(data).hexdigest()

def extract_urls(text):
    return list(set(re.findall(r'https?://[^\s<>"]+', text)))

def extract_ips(text):
    return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))

def vt_url_lookup(url):
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )
        if r.status_code != 200:
            return None

        url_id = r.json()["data"]["id"]
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers=headers,
            timeout=15
        ).json()

        stats = report["data"]["attributes"]["stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }
    except Exception:
        return None

def vt_hash_lookup(file_hash):
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers,
            timeout=15
        )
        if r.status_code != 200:
            return None

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }
    except Exception:
        return None

def parse_authentication_results(headers):
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    auth = headers.get("Authentication-Results", "")
    for k in result.keys():
        if f"{k}=pass" in auth:
            result[k] = "pass"
        elif f"{k}=fail" in auth:
            result[k] = "fail"
    return result

def ip_owner_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

# =============================
# MAIN ANALYSIS
# =============================

def analyze_email(file_path):
    loading_animation()

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    from_addr = msg.get("From", "N/A")
    to_addr = msg.get("To", "N/A")
    subject = msg.get("Subject", "N/A")
    received = msg.get_all("Received", [])
    receiving_domain = received[0] if received else "Unknown"

    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="ignore")

            if part.get_filename():
                data = part.get_payload(decode=True)
                attachments.append({
                    "filename": part.get_filename(),
                    "type": part.get_content_type(),
                    "sha256": sha256_file(data),
                    "vt": vt_hash_lookup(sha256_file(data))
                })
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")

    urls = extract_urls(body)
    ips = extract_ips(body + " ".join(received))
    auth_header = parse_authentication_results(msg)

    risk = 0
    confirmed_malware = False

    print(Fore.CYAN + "\n[ URLs ]")
    url_data = []
    url_risk = 0

    for u in urls:
        vt = vt_url_lookup(u)
        verdict = Fore.GREEN + "CLEAN"

        if vt:
            m = vt.get("malicious", 0)
            s = vt.get("suspicious", 0)

            if m >= 5:
                verdict = Fore.RED + "MALICIOUS"
                confirmed_malware = True
                url_risk += 8
            elif m > 0:
                verdict = Fore.YELLOW + "SUSPICIOUS"
                url_risk += 5
            elif s > 0:
                verdict = Fore.YELLOW + "SUSPICIOUS"
                url_risk += 2

        print(f" - {u} → {verdict}{Style.RESET_ALL}")
        url_data.append({"url": u, "virustotal": vt})

    risk += min(url_risk, 15)

    if "fail" in auth_header.values():
        risk += 4

    if len(urls) >= 5:
        risk += 5
    elif len(urls) >= 3:
        risk += 3
    elif len(urls) >= 1:
        risk += 1

    print(Fore.CYAN + "\n[ Attachments ]")
    for a in attachments:
        verdict = Fore.GREEN + "CLEAN"
        if a["vt"] and a["vt"].get("malicious", 0) > 0:
            verdict = Fore.RED + "MALICIOUS"
            risk += 8
        print(f" - {a['filename']} ({a['type']}) → {verdict}{Style.RESET_ALL}")

    print(Fore.CYAN + "\n[ Authentication ]")
    for k, v in auth_header.items():
        color = Fore.GREEN if v == "pass" else Fore.RED if v == "fail" else Fore.YELLOW
        print(f" {k.upper()} : {color}{v}{Style.RESET_ALL}")

    print(Fore.CYAN + "\n[ IPs ]")
    ip_data = []
    for ip in ips:
        owner = ip_owner_lookup(ip)
        print(f" - {ip} ({owner})")
        ip_data.append({"ip": ip, "owner": owner})

    severity = "LOW"
    if risk >= 20:
        severity = "HIGH"
    elif risk >= 10:
        severity = "MEDIUM"

    print(Fore.MAGENTA + f"\n[RISK] Score: {risk} | Severity: {severity}")

    report = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "author": AUTHOR,
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "receiving_domain": receiving_domain,
        "authentication": auth_header,
        "urls": url_data,
        "attachments": attachments,
        "ips": ip_data,
        "risk_score": risk,
        "severity": severity,
        "confirmed_malware": confirmed_malware
    }

    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)

    print(Fore.GREEN + "\n[+] JSON report saved as report.json\n")

# =============================
# ENTRY POINT
# =============================

if __name__ == "__main__":
    smells_good_banner()
    phishing_banner()

    parser = argparse.ArgumentParser(description=TOOL_NAME)
    parser.add_argument("-f", "--file", required=True, help="EML file path")
    args = parser.parse_args()

    analyze_email(args.file)
