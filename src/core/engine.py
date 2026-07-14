from src.scanner.nmap_scanner import NmapScanner
from src.parser.nmap_parser import NmapParser


class ScanEngine:

    def __init__(self):

        self.scanner = NmapScanner()
        self.parser = NmapParser()


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


        return parsed_results