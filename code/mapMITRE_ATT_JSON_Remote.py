import requests

ATTACK_TECHNIQUES_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def fetch_attack_techniques():
    response = requests.get(ATTACK_TECHNIQUES_URL)
    data = response.json()
    techniques = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            technique = {
                "id": obj.get("external_references", [{}])[0].get("external_id"),
                "name": obj.get("name"),
                "description": obj.get("description")
            }
            techniques.append(technique)
    return techniques

if __name__ == "__main__":
    enriched = fetch_attack_techniques()
    for tech in enriched[:5]:  # Show first 5 techniques
        print(f"ID: {tech['id']}, Name: {tech['name']}\nDescription: {tech['description']}\n")
