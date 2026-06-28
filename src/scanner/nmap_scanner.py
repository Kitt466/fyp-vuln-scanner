import nmap

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target):
        print(f"Scanning {target}...")

        self.nm.scan(target, arguments="-sV")

        results = {}

        for host in self.nm.all_hosts():
            results[host] = {
                "state": self.nm[host].state(),
                "ports": []
            }

            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto]:
                    service = self.nm[host][proto][port]

                    results[host]["ports"].append({
                        "port": port,
                        "name": service.get("name"),
                        "version": service.get("version")
                    })

        return results