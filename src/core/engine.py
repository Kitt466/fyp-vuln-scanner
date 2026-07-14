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

            keyword = (
                f"{service['service']} "
                f"{service['version']}"
            )


            vulnerabilities = self.nvd.search(
                keyword
            )


            service["vulnerabilities"] = vulnerabilities


        return parsed_results