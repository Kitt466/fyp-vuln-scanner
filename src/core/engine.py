from src.scanner.nmap_scanner import NmapScanner


class ScanEngine:

    def __init__(self):
        self.scanner = NmapScanner()


    def run(self, target, scan_type):

        print("[+] Starting scan...")

        results = self.scanner.scan(
        target,
        scan_type
        )

        return results