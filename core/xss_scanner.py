from bs4 import BeautifulSoup
from utils.payloads import XSS_PAYLOADS, SQLI_PAYLOADS
import logging

logger = logging.getLogger(__name__)


def test_xss(self):
    vulnerabilities = []
    test_params = [
        {"url": f"{self.target_url}/api/Feedbacks", "method": "POST", "param": "comment"},
        {"url": f"{self.target_url}/rest/products/search", "method": "GET", "param": "q"},
        {"url": f"{self.target_url}/contact", "method": "POST", "params": ["message"]}
    ]

    for test in test_params:
        for payload in XSS_PAYLOADS:
            try:
                data = {test["param"]: payload}
                response = self._make_request(test["url"], test["method"], data)

                if response and (payload in response.text or response.status_code == 201):
                    vulnerabilities.append({
                        "type": "XSS",
                        "parameter": test["param"],  # Add parameter info
                        "endpoint": f"{test['method']} {test['url']}",
                        "payload": payload,
                        "context": self._get_input_context(test["url"], test["param"])
                    })

            except Exception as e:
                logger.error(f"XSS test failed: {str(e)}")

    return vulnerabilities


def _get_input_context(self, url: str, param: str) -> str:
    """Get HTML context for parameter"""
    response = self._make_request(url)
    if response:
        soup = BeautifulSoup(response.text, 'html.parser')
        input_field = soup.find('input', {'name': param}) or soup.find('textarea', {'name': param})
        if input_field:
            return f"{input_field.get('id', '')} ({input_field.name})"
    return "Unknown context"