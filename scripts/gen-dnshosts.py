#!/usr/bin/env python3
"""Writes internal/certs/dnshosts.json: the DNS hosts lego supports and the
settings each one takes, read from lego's provider descriptions.

Run after updating github.com/go-acme/lego/v4:  python3 scripts/gen-dnshosts.py
"""
import glob, json, os, subprocess, tomllib

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lego = subprocess.check_output(["go", "list", "-m", "-f", "{{.Dir}}", "github.com/go-acme/lego/v4"], cwd=root, text=True).strip()
out = []
for f in sorted(glob.glob(os.path.join(lego, "providers/dns/*/*.toml"))):
    with open(f, "rb") as fh:
        t = tomllib.load(fh)
    if "Code" not in t:
        continue
    c = t.get("Configuration", {})
    out.append({
        "code": t["Code"],
        "name": t.get("Name", t["Code"]),
        "url": t.get("URL", ""),
        "credentials": [[k, v] for k, v in c.get("Credentials", {}).items()],
        "additional": [[k, v] for k, v in c.get("Additional", {}).items()],
    })
out.sort(key=lambda p: p["name"].lower())
with open(os.path.join(root, "internal/certs/dnshosts.json"), "w") as fh:
    json.dump(out, fh, separators=(",", ":"), ensure_ascii=False)
    fh.write("\n")
print(len(out), "DNS hosts")
