import json

with open("asset.json", encoding="utf-8") as file:
    asset = json.load(file)

print(asset["name"], asset["criticality"])
print(asset["internet_facing"])

asset["criticality"] = 500
with open("asset1.json", "w", encoding="utf-8") as file:
    json.dump(asset, file, indent=2)
    