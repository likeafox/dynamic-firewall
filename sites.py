__all__ = ["site_profiles", "site_profile_alias_map"]

import requests, builtins
from utils import *

def find_ip_addresses_in_json(obj):
    match type(obj):
        case builtins.list:
            coll = iter(obj)
        case builtins.dict:
            coll = obj.values()
        case builtins.str:
            return [obj] if is_ip4(obj) else []
        case _:
            return []
    r = []
    for el in coll:
        r += find_ip_addresses_in_json(el)
    return r

def fetch_json_refresh(url):
    def refresh(cur_addrs):
        response = requests.get(url)
        response.raise_for_status()
        return find_ip_addresses_in_json(response.json())
    return refresh

def refresh_fastly(cur_addrs):
    response = requests.get("https://api.fastly.com/public-ip-list")
    response.raise_for_status()
    return response.json()['addresses']

def refresh_wikipedia(cur_addrs):
    response = requests.get("https://wikitech.wikimedia.org/wiki/IP_and_AS_allocations")
    response.raise_for_status()
    content = response.text

    st = content.find('id="Public_IPs"')
    ed = content.find("</table>", st)
    if st == -1 or ed == -1:
        raise ValueError("unable to find wikipedia's table of IP ranges")
    seg = content[st:ed]
    cells = re.findall(r'(?:<td>\s*)(.+)(?:\s*</td>)', seg)

    return [c for c in cells if is_ip4(c)]

site_profiles = {
    "github": {
        'refresh':             fetch_json_refresh("https://api.github.com/meta"),
        'refreshIntervalMins': (60*24*5), # 5 days
    },
    "google": {
        'refresh':             fetch_json_refresh("https://www.gstatic.com/ipranges/goog.json"),
        'refreshIntervalMins': (60*24*5),
        'aliases': [
            "youtube",
        ]
    },
    "wikipedia": {
        'refresh':             refresh_wikipedia,
        'refreshIntervalMins': (60*24*60),
    },
    "fastly": {
        'refresh':             refresh_fastly,
        'refreshIntervalMins': (60*24*5),
        'aliases': [
            "pypi", #ref: https://pypi.org/help/#ips
        ]
    },
}

@(lambda f: dict(f()))
def site_profile_alias_map():
    for profname,prof in site_profiles.items():
        if 'aliases' in prof:
            for a in prof['aliases']:
                yield (a, profname)
        yield (profname, profname)
