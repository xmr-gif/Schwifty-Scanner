from utils.payloads import XSS_PAYLOADS, SQLI_PAYLOADS
import logging

logger = logging.getLogger(__name__)
def test_sqli(self):
    """SQLi detection with parameter identification"""
    test_points = [
        {"url": f"{self.target_url}/rest/products/search", "method": "GET", "param": "q"},
        {"url": f"{self.target_url}/api/Users", "method": "POST", "param": "email"}
    ]

    results = {
        "vulnerable": False,
        "vulnerabilities": [],
        "severity": "Critical"
    }

    for point in test_points:
        for payload in SQLI_PAYLOADS:
            try:
                data = {point["param"]: payload}
                response = self._make_request(
                    url=point["url"],
                    method=point["method"],
                    data=data
                )

                if self._is_sqli_vulnerable(response):
                    results["vulnerable"] = True
                    results["vulnerabilities"].append({
                        "parameter": point["param"],
                        "type": "SQLi",
                        "endpoint": f"{point['method']} {point['url']}",
                        "payload": payload,
                        "evidence": response.text[:200]
                    })

            except Exception as e:
                logger.error(f"SQLi test failed on {point['param']}: {str(e)}")

    return results