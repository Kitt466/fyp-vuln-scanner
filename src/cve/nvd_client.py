import requests


class NVDClient:

    def __init__(self):

        self.url = (
            "https://services.nvd.nist.gov/rest/json/"
            "cves/2.0"
        )


    def search(self, keyword):

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5
        }


        response = requests.get(
            self.url,
            params=params
        )


        if response.status_code != 200:
            print("Failed to retrieve CVE data")
            return []


        data = response.json()

        vulnerabilities = []


        for item in data.get("vulnerabilities", []):

            cve = item["cve"]


            cvss = None
            severity = None


            metrics = cve.get("metrics", {})


            # CVSS v3.1
            if "cvssMetricV31" in metrics:

                cvss_data = (
                    metrics["cvssMetricV31"][0]["cvssData"]
                )

                cvss = cvss_data.get("baseScore")

                severity = cvss_data.get("baseSeverity")


            # CVSS v3.0
            elif "cvssMetricV30" in metrics:

                cvss_data = (
                    metrics["cvssMetricV30"][0]["cvssData"]
                )

                cvss = cvss_data.get("baseScore")

                severity = cvss_data.get("baseSeverity")


            # CVSS v2 fallback
            elif "cvssMetricV2" in metrics:

                cvss_data = (
                    metrics["cvssMetricV2"][0]["cvssData"]
                )

                cvss = cvss_data.get("baseScore")


            vulnerabilities.append({

                "id": cve["id"],

                "cvss": cvss,

                "severity": severity,

                "description":
                    cve["descriptions"][0]["value"]

            })


        return vulnerabilities