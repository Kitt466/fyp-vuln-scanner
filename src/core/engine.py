from src.scanner.nmap_scanner import NmapScanner


class ScanEngine:

    def __init__(self):
        self.scanner = NmapScanner()


    def run(self, target):

        print("[+] Starting vulnerability assessment")

        scan_results = self.scanner.scan(target)

        return scan_results