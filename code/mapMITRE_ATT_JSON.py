import json

# Load MITRE ATT&CK techniques
with open('enterprise-attack.json', 'r', encoding='utf-8') as f:
    attack_data = json.load(f)

techniques = [obj for obj in attack_data['objects'] if obj.get('type') == 'attack-pattern']

# Example list of network logs
network_logs = [
    {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "description": "Detected spearphishing attachment sent to user"},
    {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "description": "Suspicious command and control traffic"},
    # Add more logs as needed
]

for log in network_logs:
    desc = log.get('description', '').lower()
    matched = [t['name'] for t in techniques if t['name'].lower() in desc]
    log['technique_name'] = matched[0] if matched else None

print(json.dumps(network_logs, indent=2))
