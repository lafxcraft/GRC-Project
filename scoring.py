SLA = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}

def get_level(risk):
    if risk >= 40:
        return "Critical"
    elif risk >= 25:
        return "High"
    elif risk >= 10:
        return "Medium"
    return "Low"

def best_cvss(vuln):
    scores = [c.get("V3Score", 0) for c in vuln.get("CVSS", {}).values()]
    return max(scores or [0])

def parse_trivy(data, criticality=4):
    rows = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            cvss = best_cvss(v)
            risk = round(cvss * criticality, 1)
            level = get_level(risk)
            rows.append({
                "cve": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion") or "no fix yet",
                "severity": v.get("Severity", ""),
                "cvss": cvss,
                "risk": risk,
                "level": level,
                "sla_days": SLA[level],
            })
    rows.sort(key=lambda r: r["risk"], reverse=True)
    return rows
