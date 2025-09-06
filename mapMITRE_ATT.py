import requests
import csv
from io import StringIO

# Download the MITRE ATT&CK techniques CSV
url = "https://attack.mitre.org/techniques/enterprise/techniques.csv"
response = requests.get(url)
response.raise_for_status()

# Parse CSV
csvfile = StringIO(response.text)
reader = csv.DictReader(csvfile)

# Filter and map techniques related to Network Traffic
network_traffic_techniques = []
for row in reader:
    if "Network Traffic" in row.get("Data Sources", ""):
        network_traffic_techniques.append({
            "ID": row.get("ID"),
            "Name": row.get("Name"),
            "Description": row.get("Description"),
            "Data Sources": row.get("Data Sources"),
            "Tactics": row.get("Tactics")
        })

# Print results
for tech in network_traffic_techniques:
    print(f"{tech['ID']}: {tech['Name']} | Tactics: {tech['Tactics']}")
    print(f"  Data Sources: {tech['Data Sources']}")
    print(f"  Description: {tech['Description']}\n")
