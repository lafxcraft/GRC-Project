def get_level(risk):
    if risk >= 40:
        return "Critical"
    return "Other"

finding = {"pkg": "libc6", "cvss": 9.8}
print(get_level(finding["cvss"] * 4))
print(finding["pkg"])

data = [1, 2, 3, True]
print(data[3])