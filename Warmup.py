levels = ["Low", "High", "Critical"]
finding = {"pkg": "libc6", "cvss": 9.8}

def double(n):
    return n * 2

print(levels[1])
print(finding["cvss"])
print(double(4) + 1)
print(len(finding))


scores = [9.5, 5.0, 7.5, 2.0, 9.0]

high = []
for score in scores:
    if score >= 7:
        high.append(score)

print("All:", scores)
print("High:", high)
print("Max:", max(scores))
print("Average:", sum(scores) / len(scores))
