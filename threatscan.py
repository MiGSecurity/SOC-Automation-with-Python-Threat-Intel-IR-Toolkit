# SOC Automation with Python – Threat Intel & Incident Response Toolkit
import configparser
from datetime import datetime
import json
import argparse
import requests
import shodan
from OTXv2 import OTXv2, IndicatorTypes
from colorama import init, Fore, Style
init(autoreset=True)

# Load config
config = configparser.ConfigParser()
config.read('config.ini')

# Grab API keys
VirusTotal_API = config['API_KEYS']['VIRUSTOTAL']
AbuseIPDB_API = config['API_KEYS']['ABUSEIPDB']
Shodan_API = config['API_KEYS']['SHODAN']
OTX_API = config['API_KEYS']['OTX']

# === VIRUSTOTAL LOOKUP ===


def vt_lookup_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VirusTotal_API}
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.status_code == 200 else None


# === AbuseIPDB LOOKUP===
def abuseipdb_lookup(ip, abuse_api):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90  # You can reduce/increase this depending on how fresh you want it
    }
    headers = {
        "Key": abuse_api,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        return {"error": f"AbuseIPDB error: {response.status_code}"}

    result = response.json()["data"]
    return {
        "abuse_confidence_score": result.get("abuseConfidenceScore"),
        "country": result.get("countryCode"),
        "domain": result.get("domain"),
        "isp": result.get("isp"),
        "total_reports": result.get("totalReports"),
        "last_reported": result.get("lastReportedAt"),
        "usage_type": result.get("usageType"),
        "categories": result.get("categories")
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

        # Grab banner info from each service
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


def print_shodan(data):
    print(Fore.MAGENTA + "\n[+] Shodan:")
    if "error" in data:
        print(Fore.RED + Style.BRIGHT + "    Error: " + data["error"])
        return

    print(f"    • Organization: {data['org']}")
    print(f"    • Hostnames: {', '.join(data['hostnames'])}")
    print(f"    • OS: {data['os']}")
    print(f"    • Open Ports: {data['ports']}")
    print(f"    • Services:")
    for s in data['services']:
        port = s['port']
        product = s.get('product', 'Unknown')
        version = s.get('version', '')
        print(Fore.LIGHTBLUE_EX + f"      - Port {port}: {product} {version}")

# === PARSE RESPONSE ===


def extract_summary(data):
    attr = data['data']['attributes']
    summary = {
        "ip": data['data']['id'],
        "malicious_count": attr['last_analysis_stats']['malicious'],
        "harmless_count": attr['last_analysis_stats']['harmless'],
        "votes": attr.get('total_votes', {}),
        "owner": attr.get('as_owner'),
        "network": attr.get('network'),
        "context": attr.get('crowdsourced_context', []),
        "tags": attr.get('tags', [])
    }
    return summary

# === RISK SCORING ===


def score_indicator(summary):
    score = summary["malicious_count"]

    # Context-based boost
    context = summary.get("context", [])
    for item in context:
        if "C2" in item.get("details", "").lower():
            score += 3

    # AbuseIPDB boost
    abuse_score = summary.get("abuseipdb", {}).get("abuse_confidence_score", 0)
    if abuse_score >= 80:
        score += 2

    # Shodan port-based boost
    risky_ports = {22, 23, 445, 3389}
    open_ports = set(summary.get("shodan", {}).get("ports", []))
    if risky_ports & open_ports:
        score += 2

    # Final verdict
    if score >= 10:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def color_severity(severity):
    if severity == "LOW":
        return Fore.GREEN + severity
    elif severity == "MEDIUM":
        return Fore.YELLOW + severity
    else:
        return Fore.RED + Style.BRIGHT + severity
# === LOGGING ===


def log_to_file(summary, severity):
    summary["severity"] = severity
    summary["timestamp"] = datetime.utcnow().isoformat()
    with open("lookup_log.json", "a") as f:
        f.write(json.dumps(summary) + "\n")


def print_abuseipdb(data):
    print(Fore.MAGENTA + "\n[+] AbuseIPDB:")
    if "error" in data:
        print(Fore.RED + Style.BRIGHT + "    " + data["error"])
        return

    print(f"    • Abuse Score: {data['abuse_confidence_score']} / 100")
    print(f"    • Total Reports: {data['total_reports']}")
    print(f"    • Last Reported: {data['last_reported']}")
    print(f"    • ISP: {data['isp']}")
    print(f"    • Country: {data['country']}")
    print(f"    • Usage Type: {data['usage_type']}")
    print(f"    • Categories: {data['categories']}")

# === MAKING THINGS PRETYY!===


def pretty_print(summary):
    def colorize_key(key):
        highlight = {
            "ip": Fore.CYAN,
            "network": Fore.CYAN,
            "owner": Fore.CYAN,
            "malicious_count": Fore.RED,
            "harmless_count": Fore.GREEN,
            "abuse_confidence_score": Fore.YELLOW,
            "votes": Fore.BLUE,
            "score": Fore.YELLOW,
            "banner": Fore.LIGHTYELLOW_EX,  # NEW distinct color
            "port": Fore.LIGHTBLUE_EX,
            "services": Fore.LIGHTMAGENTA_EX,
            "context": Fore.LIGHTCYAN_EX
        }
        return highlight.get(key, Fore.WHITE) + key + Style.RESET_ALL

    def recurse(data, indent=0):
        spacer = "  " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"{spacer}{colorize_key(str(key))}: ", end="")
                recurse(value, indent + 1)
        elif isinstance(data, list):
            print()
            for item in data:
                recurse(item, indent + 1)
        else:
            print(f"{Fore.WHITE}{data}{Style.RESET_ALL}")

    recurse(summary)


# ===SOBMIT TO OTX ===
def submit_to_otx(ip, description, api_key):
    otx = OTXv2(api_key)

    pulse_name = f"Suspicious IP - {ip}"
    indicators = [
        {
            "indicator": ip,
            "type": IndicatorTypes.IPv4,
            "title": f"High risk IP observed by threattool",
            "description": description,
            "severity": 3  # scale 1-4 (low to critical)
        }
    ]

    try:
        result = otx.create_pulse(
            name=pulse_name,
            indicators=indicators,
            public=True,  # or False if you want to keep it private
            tags=["threattool", "auto", "malicious-ip"],
            references=[],
            description=description
        )
        print(Fore.GREEN + f"[+] Submitted pulse to OTX: {result['id']}")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to submit to OTX: {e}")

# === MAIN ENTRY POINT ===


def main():
    if not all([VirusTotal_API, AbuseIPDB_API, Shodan_API, OTX_API]):
        print(Fore.RED + "[!] Missing one or more API keys in config.ini")
        exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('--indicator', type=str,
                        required=True, help="IP or domain to look up")
    args = parser.parse_args()

    data = vt_lookup_ip(args.indicator)
    if not data:
        print("[!] API Error or Invalid Response.")
        return

    summary = extract_summary(data)

    abuse_summary = abuseipdb_lookup(args.indicator, AbuseIPDB_API)
    summary["abuseipdb"] = abuse_summary

    severity = score_indicator(summary)
    if severity == "HIGH":
        desc = f"IP {args.indicator} flagged as HIGH severity by threattool.\n"
        desc += f"Votes: {summary['votes']}, Abuse Score: {summary['abuseipdb']['abuse_confidence_score']}\n"
        submit_to_otx(args.indicator, desc, OTX_API)
    shodan_result = shodan_lookup(args.indicator, Shodan_API)
    summary["shodan"] = shodan_result

    print(Fore.CYAN + f"\n[+] Summary for {args.indicator}:\n")
    pretty_print(summary)
    print(f"\n[+] Scored Threat Level: {color_severity(severity)}")
    print_shodan(shodan_result)

    log_to_file(summary, severity)
    print(Fore.CYAN + Style.BRIGHT + f"\n[✓] Result logged to lookup_log.json")
    print(Fore.YELLOW + Style.BRIGHT +
          f"[!] FINAL VERDICT: {color_severity(severity)} RISK for {args.indicator}")


if __name__ == "__main__":
    main()
