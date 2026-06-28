from src.scanner.nmap_scanner import NmapScanner
import json

scanner = NmapScanner()

target = input("Enter target IP: ")

results = scanner.scan(target)

print(json.dumps(results, indent=4))