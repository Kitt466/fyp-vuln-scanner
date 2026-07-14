class NmapParser:

    def parse(self, scan_results):

        parsed_results = []


        for host, data in scan_results.items():

            for port in data["ports"]:

                parsed_results.append({

                    "host": host,

                    "port": port["port"],

                    "protocol": port["protocol"],

                    "service": port["product"] or port["name"],

                    "version": port["version"],

                    "state": port["state"]

                })


        return parsed_results