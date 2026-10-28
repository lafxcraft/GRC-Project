packages = ["openssl", "libc6", "zlib1g",
            "openssl", "libc6", "openssl"]

counts = {}
for pkg in packages:
    counts[pkg] = counts.get(pkg, 0) + 1

print(counts)
for pkg, n in counts.items():
    print(pkg, "appears", n, "times")
    