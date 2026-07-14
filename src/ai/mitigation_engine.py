class MitigationEngine:

    def generate(self, vulnerability, context):

        return {
            "recommendation":
            "Apply security patch and restrict access",
            
            "reason":
            f"Asset {context.asset_name} has {context.criticality} importance"
        }