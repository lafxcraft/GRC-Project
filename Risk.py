import json
import pandas as pd

ASSET_CRITICALITY = 5   # 1-5 scale

data = json.load(open("trivy.json", encoding="utf-8"))
rows = []
for res in data.get("Results", []):
    for v in res.get("Vulnerabilities", []):
        scores = [c.get("V3Score", 0) for c in v.get("CVSS", {}).values()]
        cvss = max(scores or [0])
        rows.append({"cve": v["VulnerabilityID"],
                     "pkg": v["PkgName"], "cvss": cvss})
                     
def level(r):
    return ("Critical" if r >= 40 else "High" if r >= 25
            else "Medium" if r >= 10 else "Low")

SLA = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}

df = pd.DataFrame(rows)
df["risk"] = df["cvss"] * ASSET_CRITICALITY
df["level"] = df["risk"].apply(level)
df["sla_days"] = df["level"].map(SLA)
df = df.sort_values("risk", ascending=False)
df.to_csv("risk_register.csv", index=False)
print(df.head(10))
order = ["Critical", "High", "Medium", "Low"]
print(df["level"].value_counts().reindex(order, fill_value=0))