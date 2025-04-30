# SOC Automation with Python – Threat Intel & Incident Response Toolkit
import configparser
from datetime import datetime
import json
import argparse
import requests
import shodan
import base64
from OTXv2 import OTXv2, IndicatorTypes
from colorama import init, Fore, Style

init(autoreset=True)

# Load config
config = configparser.ConfigParser()
config.read('config.ini')
print("Loaded files:", config.read('config.ini'))
print("Sections found:", config.sections())


VirusTotal_API = config['API_KEYS']['VIRUSTOTAL']
AbuseIPDB_API = config['API_KEYS']['ABUSEIPDB']
Shodan_API = config['API_KEYS']['SHODAN']
OTX_API = config['API_KEYS']['OTX']


# === VIRUSTOTAL LOOKUPS ===


def vt_lookup_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VirusTotal_API}
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.status_code == 200 else None


def vt_lookup_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VirusTotal_API}
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.status_code == 200 else None


def vt_lookup_url(raw_url):
    url_id = base64.urlsafe_b64encode(raw_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VirusTotal_API}
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.status_code == 200 else None

# === AbuseIPDB LOOKUP ===


def abuseipdb_lookup(ip, abuse_api):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": abuse_api, "Accept": "application/json"}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code != 200:
        return {"error": f"AbuseIPDB error: {resp.status_code}"}
    d = resp.json().get("data", {})
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"),
        "domain": d.get("domain"),
        "isp": d.get("isp"),
        "total_reports": d.get("totalReports"),
        "last_reported": d.get("lastReportedAt"),
        "usage_type": d.get("usageType"),
        "categories": d.get("categories")
    }

# === SHODAN LOOKUP ===


def shodan_lookup(ip, api_key):
    api = shodan.Shodan(api_key)
    try:
        host = api.host(ip)
        result = {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "hostnames": host.get("hostnames", []),
            "ports": host.get("ports", []),
            "services": []
        }
        for item in host.get("data", []):
            result["services"].append({
                "port": item.get("port"),
                "banner": item.get("data"),
                "product": item.get("product"),
                "version": item.get("version"),
                "transport": item.get("transport"),
                "tags": item.get("tags")
            })
        return result
    except shodan.APIError as e:
        return {"error": str(e)}

# === PARSE RESPONSE ===


def extract_summary(data):
    attr = data['data']['attributes']
    return {
        "ip": data['data']['id'],
        "malicious_count": attr['last_analysis_stats']['malicious'],
        "harmless_count": attr['last_analysis_stats']['harmless'],
        "votes": attr.get('total_votes', {}),
        "owner": attr.get('as_owner'),
        "network": attr.get('network'),
        "context": attr.get('crowdsourced_context', []),
        "tags": attr.get('tags', [])
    }

# === RISK SCORING ===


def score_indicator(summary):
    score = summary["malicious_count"]
    for item in summary.get("context", []):
        if "C2" in item.get("details", "").lower():
            score += 3
    abuse = summary.get("abuseipdb", {}).get("abuse_confidence_score", 0)
    if abuse >= 80:
        score += 2
    risky = {22, 23, 445, 3389}
    openp = set(summary.get("shodan", {}).get("ports", []))
    if risky & openp:
        score += 2
    if score >= 10:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def color_severity(sev):
    if sev == "LOW":
        return Fore.GREEN + sev
    if sev == "MEDIUM":
        return Fore.YELLOW + sev
    return Fore.RED + Style.BRIGHT + sev

# === LOGGING ===


def log_to_file(summary, sev):
    summary["severity"] = sev
    summary["timestamp"] = datetime.utcnow().isoformat()
    with open("lookup_log.json", "a") as f:
        f.write(json.dumps(summary) + "\n")

# === PRETTY PRINT ===


def pretty_print(summary):
    def colorize_key(k):
        col = {
            "ip": Fore.CYAN, "network": Fore.CYAN, "owner": Fore.CYAN,
            "malicious_count": Fore.RED, "harmless_count": Fore.GREEN,
            "abuse_confidence_score": Fore.YELLOW, "votes": Fore.BLUE,
            "banner": Fore.LIGHTYELLOW_EX, "port": Fore.LIGHTBLUE_EX,
            "services": Fore.LIGHTMAGENTA_EX, "context": Fore.LIGHTCYAN_EX
        }
        return col.get(k, Fore.WHITE) + k + Style.RESET_ALL

    def recurse(d, indent=0):
        sp = "  " * indent
        if isinstance(d, dict):
            for k, v in d.items():
                print(f"{sp}{colorize_key(str(k))}: ", end="")
                recurse(v, indent+1)
        elif isinstance(d, list):
            print()
            for i in d:
                recurse(i, indent+1)
        else:
            print(Fore.WHITE + str(d) + Style.RESET_ALL)

    recurse(summary)

# === OTX SUBMISSION ===


def submit_to_otx(ip, desc, api_key):
    otx = OTXv2(api_key)
    pulse = [{"indicator": ip, "type": IndicatorTypes.IPv4,
              "title": f"High risk IP {ip}",
              "description": desc, "severity": 3}]
    try:
        res = otx.create_pulse(name=f"Suspicious IP - {ip}",
                               indicators=pulse, public=True,
                               tags=["threattool"], references=[],
                               description=desc)
        print(Fore.GREEN + f"[+] Pulse submitted: {res['id']}")
    except Exception as e:
        print(Fore.RED + f"[!] OTX submit failed: {e}")


def already_in_otx(ip, otx):
    try:
        pulses = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        return len(pulses.get('pulse_info', {}).get('pulses', [])) > 0
    except:
        return False

# === MAIN ===


def main():
    if not all([VirusTotal_API, AbuseIPDB_API, Shodan_API, OTX_API]):
        print(Fore.RED + "[!] Missing API key(s) in config.ini")
        exit(1)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-help', '--help',
                        action='help',
                        help='show this help message and exit')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', dest='indicator',
                       help='IP address to look up')
    group.add_argument('-u', '--url', help='URL to look up')
    group.add_argument('-h', '--hash', dest='file_hash',
                       help='File hash to look up')
    args = parser.parse_args()

    if args.indicator:
        data = vt_lookup_ip(args.indicator)
        label = args.indicator
    elif args.url:
        data = vt_lookup_url(args.url)
        label = args.url
    else:
        data = vt_lookup_hash(args.file_hash)
        label = args.file_hash

    if not data:
        print(Fore.RED + "[!] VT error or no data.")
        return

    summary = extract_summary(data)

    if args.indicator:
        summary["abuseipdb"] = abuseipdb_lookup(args.indicator, AbuseIPDB_API)
        summary["shodan"] = shodan_lookup(args.indicator, Shodan_API)
    else:
        summary["abuseipdb"] = {}
        summary["shodan"] = {}

    sev = score_indicator(summary)
    if sev == "HIGH" and args.indicator:
        otx = OTXv2(OTX_API)
        if not already_in_otx(args.indicator, otx):
            desc = f"IP {label} flagged HIGH. Votes: {summary['votes']}"
            submit_to_otx(label, desc, OTX_API)
        else:
            print(Fore.YELLOW + "[~] Already in OTX.")

    print(Fore.CYAN + f"\n[+] Summary for {label}:\n")
    pretty_print(summary)
    print(f"\n[+] Threat Level: {color_severity(sev)}")

    if args.indicator:
        # detailed prints
        print(Fore.MAGENTA + "\n[+] AbuseIPDB:")
        if summary["abuseipdb"].get("error"):
            print(Fore.RED + summary["abuseipdb"]["error"])
        else:
            print(
                f"  • Score: {summary['abuseipdb']['abuse_confidence_score']}")
            print(f"  • Reports: {summary['abuseipdb']['total_reports']}")
        print_shodan(summary["shodan"])

    log_to_file(summary, sev)
    print(Fore.CYAN + Style.BRIGHT + "\n[✓] Logged.")
    print(Fore.YELLOW + Style.BRIGHT +
          f"[!] FINAL VERDICT: {color_severity(sev)} RISK for {label}")


if __name__ == "__main__":
    main()
