class AssetContext:

    def __init__(self):

        self.business_name = None
        self.asset_name = None
        self.criticality = None
        self.internet_facing = False
        self.sensitive_data = False


    def collect(self):

        self.asset_name = input("Asset name: ")
        self.business_name = input("Business function: ")

        self.criticality = input(
            "Criticality (Low/Medium/High): "
        )

        self.internet_facing = input(
            "Internet facing? (yes/no): "
        )

        self.sensitive_data = input(
            "Contains sensitive data? (yes/no): "
        )

        return self