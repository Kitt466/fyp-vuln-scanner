from src.scanner.nmap_scanner import NmapScanner
from src.parser.nmap_parser import NmapParser
from src.cve.nvd_client import NVDClient


class ScanEngine:

    def __init__(self):

        self.scanner = NmapScanner()

        self.parser = NmapParser()

        self.nvd = NVDClient()


    def run(self, target, scan_type):

        print("[+] Starting scan...")


        scan_results = self.scanner.scan(
            target,
            scan_type
        )


        print("[+] Parsing results...")


        parsed_results = self.parser.parse(
            scan_results
        )


        print("[+] Searching vulnerabilities...")


        for service in parsed_results:

            version = service.get("version")


            # Only perform CVE lookup when
            # Nmap provides a version number
            if version:

                keyword = (
                    f"{service['service']} "
                    f"{version}"
                )


                vulnerabilities = self.nvd.search(
                    keyword
                )


            else:

                vulnerabilities = []


            service["vulnerabilities"] = vulnerabilities


        return parsed_results