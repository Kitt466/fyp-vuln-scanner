from src.core.engine import ScanEngine
import json


engine = ScanEngine()


target = input("Enter target IP: ")


print("""
Choose scan type:

1. Quick Scan
2. Service Detection
3. OS Detection
4. Vulnerability Scan
5. Full Scan
""")


choice = input("Select option: ")


scan_types = {

    "1": "quick",

    "2": "service",

    "3": "os",

    "4": "vulnerability",

    "5": "full"

}


scan_type = scan_types.get(
    choice,
    "service"
)


results = engine.run(
    target,
    scan_type
)


print(json.dumps(results, indent=4))