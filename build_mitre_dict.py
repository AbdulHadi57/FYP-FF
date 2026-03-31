import json
import urllib.request
import re

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
print("Downloading MITRE ATT&CK STIX database...")
req = urllib.request.Request(url)
with urllib.request.urlopen(req) as response:
    data = json.loads(response.read().decode())

out = {}
for obj in data.get('objects', []):
    if obj.get('type') == 'attack-pattern':
        ext_refs = obj.get('external_references', [])
        mitre_id = None
        for ref in ext_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                break
        
        if mitre_id:
            name = obj.get('name', 'Unknown')
            desc = obj.get('description', 'No description provided.')
            
            # clean desc
            desc = re.sub(r'\[.*?\]\(.*?\)', '', desc) # remove markdown links
            desc = desc.split('\n')[0][:200]
            if len(desc) == 200:
                desc += "..."
            
            tactics = obj.get('kill_chain_phases', [])
            tactic_name = "Uncategorized"
            if tactics:
                # 'phase_name' is typically like 'command-and-control', turn to 'Command and Control'
                tactic_name = tactics[0].get('phase_name', '').replace('-', ' ').title()
            
            out[mitre_id] = {
                "name": name,
                "tactic": tactic_name,
                "desc": desc,
                "severity": "Medium"  # default
            }

with open("frontend/src/MITRE_DICT.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

print(f"Generated frontend/src/MITRE_DICT.json with {len(out)} techniques")
