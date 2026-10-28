import json

with open("practice.json", encoding="utf-8") as file:
    data = json.load(file)

total = 0
for result in data["results"]:
    print(result["target"])
    for v in result["vulnerabilities"]:
        print("   ", v["id"], v["pkg"], v["cvss"])
        total = total + 1

        print("Total:", total)