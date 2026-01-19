import os
import json
import time
import platform
import requests
from datetime import datetime, timezone, timedelta

auth_info = {
        "discord_webhookurl": None,
        "nvdapi_key": None
}

def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

if not os.path.isfile("auth.json"):
    print("\u001b[32m[ * ]\u001b[0m Welcome it appears it is your first time...")
    print("\u001b[33m[ \u001b[32m* \033[33m]\u001b[0m Let's get started with the setup process...")
    discordwebhook_url = input("Please provide your discord webhook url: ")
    nvdapi_key = input("Please provide your nvdapi key: ")
    auth_info["discord_webhookurl"] = discordwebhook_url
    auth_info["nvdapi_key"] = nvdapi_key
    with open("auth.json", "w") as f:
        f.write(json.dumps(auth_info))
    print("Alright we just finished the setup process...")
    print("Loading...")
    time.sleep(5)
    clear_screen()
else:
    with open("auth.json", "r") as f:
        auth_info = json.loads(f.read())
sleep_hours = 5
sleep_time = sleep_hours * 60 * 60 # convert sleep hours to seconds
start_time_iso = None
end_time_iso = None
results_per_page = 60
circlapi_url = "https://cve.circl.lu/api/cve"
blacklist_domains = ["phpguru", "phpgurukul"]
color_map = {
        "critical": 0xff0000,
        "high": 0x00ff00,
        "medium": 0x0000ff,
        "low": 0x0000ff,
        "unknown": 0xffffff
}

def get_vulns_nvd():
    lookback_minutes = 360
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=lookback_minutes)
    start_time_iso = start_time.isoformat().replace("+00:00", "Z")
    end_time_iso = now.isoformat().replace("+00:00", "Z")
    nvdapi_info = {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "headers": {
            "apiKey": auth_info["nvdapi_key"]
        },
        "params":{
            "pubStartDate": start_time_iso,
            "pubEndDate": end_time_iso,
            "resultsPerPage": results_per_page
        }
    }
    vulns = None
    print("[ * ] Searching for new vulnerabilities...\n")
    try:
        r = requests.get(nvdapi_info["url"], headers=nvdapi_info["headers"],
                params=nvdapi_info["params"])
        response_json = r.json()
        vulns = response_json["vulnerabilities"]
    except:
        pass
    return vulns

def get_exploitinfo_circlapi(cve_id):
    print(f"\u001b[33m[ \u001b[34m* \u001b[33m] Gathering exploit info for {cve_id}\u001b[0m...\n")
    try:
        circl_url = requests.get(f"{circlapi_url}/{cve_id}")
    except:
        print(f"[\u001b[31m * \u001b[0m] Failed to gather exploit info...")
    return circl_url.json()

def send_cveinfo(webhook_url, data):
    while True:
        try:
            print("\033[32m[ * ]\033[0m Sending CVE....\n")
            r = requests.post(auth_info["discord_webhookurl"], json=data)
            break
        except:
            print("\033[32m[ \033[31m* \033[32m]\033[0m Sending CVE info failed...")
            print("Retrying...")

def get_english_description(descriptions):
    for description in descriptions:
        if description["lang"].lower() == "en":
            return description
    return None
def get_cve_english_description(cve):
    descriptions = cve["descriptions"]
    return get_english_description(descriptions)["value"]

def get_circlenglish_problemtype(problems):
    problem = get_english_description(problems)
    if not problem:
        return None
    return problem["description"]

def get_problemtype(exploit_info):
    try:
        problems = exploit_info["problemTypes"]
    except:
        return ""
    for problem in problems:
        current = get_circlenglish_problemtype(problem["descriptions"])
        if current:
            return " - " + current
    return ""

def cve_description_isvalid(description):
    description = description.lower()
    if "rejected" in description or "not used" in description:
        return False
    return True

def get_valid_references(refs):
    valid_refs = []
    for ref in refs:
        url = ref["url"]
        url_dup = url.lower().replace(" ", "")
        if any(blacklist in url for blacklist in blacklist_domains):
            continue
        valid_refs.append(url)
    return valid_refs

def get_cve_metrics(cve):
    metrics = None
    try:
        metrics = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    except:
        try:
            metrics = cve["metrics"]["cvssMetricV2"][0]
        except:
            pass
    return metrics

def get_cve_severity(cve):
    metrics = get_cve_metrics(cve)
    severity = "UNKNOWN"
    if metrics:
        try:
            severity = metrics["baseSeverity"]
        except:
            pass
    return severity

def add_cveinfo(cve):
    global cve_map
    cve_id = cve["id"]
    if cve_id in cve_map:
        return False
    cve_description = get_cve_english_description(cve)
    if not cve_description_isvalid(cve_description):
        return False
    references = get_valid_references(cve["references"])
    exploit_data = get_exploitinfo_circlapi(cve_id)
    exploit_info = None
    problem_type = ""
    exploit_references = None
    try:
        exploit_info = exploit_data["containers"]["cna"]
        exploit_references = get_valid_references(exploit_info["references"])
        problem_type = get_problemtype(exploit_info)
    except:
        print("Failed to get exploit data either no data exists...")
    published_date = cve["published"]
    severity = get_cve_severity(cve)
    embed_color = color_map[severity.lower()]
    cve_info = {
        "id": cve_id,
        "problem_type": problem_type,
        "severity": severity,
        "description": cve_description,
        "references": references,
        "exploit_references": exploit_references,
        "published_date": published_date,
        "embed_title": f"{cve_id}{problem_type}",
        "embed_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "embed_color": embed_color
    }
    print(f"\u001b[32m[\u001b[34m * \u001b[32m] \u001b[0mAdding {cve_id} to database...\n") 
    cve_map[cve_id] = cve_info
    return True

def create_cve_embed(cve):
    global cve_map
    cve_id = cve["id"]
    cve = cve_map[cve_id]
    references = ""
    if cve["references"]:
        references = "\n".join(cve["references"])

    exploit_references = ""
    if cve["exploit_references"]:
        exploit_references = "\n".join(cve["exploit_references"])

    embed = {
        "title": cve["embed_title"],
        "url": cve["embed_url"],
        "color": cve["embed_color"],
        "fields":[
            {
                "name": "**Severity**",
                "value": cve["severity"],
                "inline": False
            },
            {
                "name": "**References**",
                "value": references,
                "inline": False
            },
            {
                "name": "**Exploit References**",
                "value": exploit_references,
                "inline": False
            },
            {
                "name": "**Published Date**",
                "value": cve["published_date"]
            }
        ],
        "description": f"```{cve['description']}```"
    }
    return embed

def load_database():
    if not os.path.isfile("database.json"):
        return {}
    with open("database.json", "r") as f:
        loaded_data = json.loads(f.read())
    return loaded_data


cve_map = load_database()
ascii_art = """\u001b[33m
███████╗██╗   ██╗███╗   ███╗███████╗███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗ 
██╔════╝██║   ██║████╗ ████║██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
█████╗  ██║   ██║██╔████╔██║█████╗  ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝
██╔══╝  ██║   ██║██║╚██╔╝██║██╔══╝  ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║     ╚██████╔╝██║ ╚═╝ ██║███████╗███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║
╚═╝      ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

\u001b[32mversion\u001b[0m: 0.1
"""                                                                                            
while True:
    print(ascii_art)
    print("\u001b[32m[ \u001b[33m* \u001b[32m]\u001b[0m Starting enumeration process...\n")
    vulns = get_vulns_nvd()
    for count, vuln in enumerate(vulns):
            cve = vuln["cve"]
            if not add_cveinfo(cve):
                continue
            embed = create_cve_embed(cve)
            data = {"embeds": [embed]}
            send_cveinfo(webhook_url, data)
    with open("database.json", "w") as f:
        f.write(json.dumps(cve_map))
    print(f"\n\u001b[33m[ \u001b[32m* \u001b[33m] Searching within the next {sleep_hours} hour/s\033[32m...")
    time.sleep(sleep_time)
    clear_screen()
