#!/usr/bin/env python3
"""Stand-in for the nmap binary in tests. Behaviour is chosen with FAKE_NMAP_MODE:
ok (default) | slow | root."""
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
mode = os.environ.get("FAKE_NMAP_MODE", "ok")

if args and args[0] in ("--version", "-V"):
    print("Nmap version 7.94 ( https://nmap.org )")
    sys.exit(0)

if mode == "root":
    print("You requested a scan type which requires root privileges.")
    print("QUITTING!")
    sys.exit(1)

xml_out = args[args.index("-oX") + 1]
print("Starting Nmap 7.94 ( https://nmap.org )", flush=True)
print("Discovered open port 22/tcp on 10.0.0.5", flush=True)
print("SYN Stealth Scan Timing: About 40.00% done; ETC: 15:00 (0:00:05 remaining)", flush=True)
if mode == "slow":
    for _ in range(200):
        print("Service scan Timing: About 10.00% done; ETC: 15:10", flush=True)
        time.sleep(0.05)
print("Discovered open port 80/tcp on 10.0.0.5", flush=True)
print("Service scan Timing: About 90.00% done; ETC: 15:00 (0:00:01 remaining)", flush=True)
shutil.copyfile(os.path.join(HERE, "nmap_sample.xml"), xml_out)
print("Nmap done: 2 IP addresses (1 host up) scanned", flush=True)
