import nmap


class NmapScanner:

    def __init__(self):
        self.nm = nmap.PortScanner()


    def scan(self, target, scan_type="service"):

        print(f"Scanning {target}...")

        scan_profiles = {

            "quick": "-F",

            "service": "-sV",

            "os": "-O",

            "vulnerability": "-sV --script vuln",

            "full": "-sV -O --script vuln"
        }


        arguments = scan_profiles.get(
            scan_type,
            "-sV"
        )


        print(f"Scan type: {scan_type}")
        print(f"Nmap arguments: {arguments}")


        self.nm.scan(
            target,
            arguments=arguments
        )


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

                        "protocol": proto,

                        "name": service.get("name"),

                        "product": service.get("product"),

                        "version": service.get("version"),

                        "state": service.get("state")

                    })


        return results