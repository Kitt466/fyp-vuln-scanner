from src.cve.nvd_client import NVDClient


client = NVDClient()


results = client.search(
    "Apache 2.4.49"
)


for cve in results:
    print(cve)