class RiskEngine:

    def __init__(self):
        pass


    def calculate_risk(self, vulnerability, service):

        cvss = vulnerability.get(
            "cvss",
            0
        )


        version = service.get(
            "version"
        )


        product = service.get(
            "service"
        )


        # Determine confidence based on detection quality

        if version and product:

            confidence = "HIGH"

        elif product:

            confidence = "MEDIUM"

        else:

            confidence = "LOW"



        # Base risk score

        risk_score = cvss



        # Adjust based on confidence

        if confidence == "HIGH":

            risk_score += 1


        elif confidence == "LOW":

            risk_score -= 1



        # Limit score

        if risk_score > 10:

            risk_score = 10


        if risk_score < 0:

            risk_score = 0



        # Determine priority

        if risk_score >= 9:

            priority = "CRITICAL"


        elif risk_score >= 7:

            priority = "HIGH"


        elif risk_score >= 4:

            priority = "MEDIUM"


        else:

            priority = "LOW"



        return {

            "cve": vulnerability.get(
                "id"
            ),

            "cvss": cvss,

            "risk_score": risk_score,

            "priority": priority,

            "confidence": confidence,

            "service": product,

            "version": version

        }