# core/scanner_engine.py
import concurrent.futures
import time
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from typing import Dict, List
import logging
from utils.payloads import XSS_PAYLOADS, SQLI_PAYLOADS
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class ScannerEngine:
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01"
        }
        self.progress = None
        self._authenticate()

    def _validate_vulnerability_entry(self, entry: dict) -> dict:
        """Ensure all vulnerability entries have required keys"""
        required_keys = ["type", "parameter", "payload"]
        optional_keys = ["evidence", "endpoint", "context", "form_action"]

        for key in required_keys:
            entry[key] = entry.get(key, "Unknown")
        for key in optional_keys:
            entry[key] = entry.get(key, "")
        return entry

    def _is_sqli_response(self, response: requests.Response) -> bool:
        """Enhanced SQLi detection with status code check"""
        if not response:
            return False
        return (
                response.status_code == 500 or
                any(err in response.text for err in [
                    "SQLITE_ERROR", "syntax error",
                    "UNION", "SELECT", "WHERE 1=1"
                ])
        )

    def _authenticate(self):
        """Bypass Juice Shop authentication using SQLi"""
        login_url = f"{self.target_url}/rest/user/login"
        payload = {"email": "' or 1=1--", "password": "password"}
        try:
            response = self.session.post(login_url, json=payload, verify=False, timeout=10)
            if response.status_code == 200:
                logger.info("Successfully authenticated using SQLi")
            else:
                logger.warning("Authentication failed")
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")

    def _make_request(self, url: str, method: str = "GET", data: dict = None):
        """Enhanced request handler with cache busting"""
        try:
            if method.upper() == "GET":
                data = data or {}
                data["_cache_buster"] = str(time.time())
                return self.session.get(
                    url,
                    headers=self.headers,
                    params=data,
                    verify=False,
                    timeout=15
                )
            else:
                return self.session.post(
                    url,
                    headers=self.headers,
                    json=data,
                    verify=False,
                    timeout=15
                )
        except Exception as e:
            logger.error(f"Request failed: {str(e)}")
            return None

    def test_xss(self):
        """XSS detection with DOM-based checks"""
        vulnerabilities = []
        test_points = [
            ("/api/Feedbacks", "POST", "comment"),
            ("/rest/products/search", "GET", "q"),
            ("/contact", "POST", "message")
        ]

        for endpoint, method, param in test_points:
            for payload in XSS_PAYLOADS:
                try:
                    data = {param: payload}
                    response = self._make_request(
                        f"{self.target_url}{endpoint}",
                        method,
                        data=data
                    )

                    if response and (payload in response.text or "<script>" in response.text):
                        vulnerabilities.append(self._validate_vulnerability_entry({
                            "type": "XSS",
                            "parameter": param,
                            "payload": payload,
                            "endpoint": f"{method} {endpoint}",
                            "context": self._get_input_context(endpoint, param)
                        }))
                except Exception as e:
                    logger.error(f"XSS test failed: {str(e)}")
        return vulnerabilities

    def _get_input_context(self, endpoint: str, param: str) -> str:
        """Get HTML context for form inputs"""
        response = self._make_request(f"{self.target_url}{endpoint}")
        if not response:
            return "Unknown context"

        soup = BeautifulSoup(response.text, 'html.parser')
        input_field = soup.find('input', {'name': param}) or soup.find('textarea', {'name': param})
        return input_field.get('id', '') if input_field else "Unknown field"

    def test_sqli(self):
        """SQLi detection with parameter tracking"""
        test_points = [
            ("/rest/products/search", "GET", "q"),
            ("/api/Users", "POST", "email"),
            ("/rest/user/login", "POST", "email")
        ]

        results = {
            "vulnerable": False,
            "vulnerabilities": []
        }

        for endpoint, method, param in test_points:
            for payload in SQLI_PAYLOADS:
                try:
                    data = {param: payload}
                    response = self._make_request(
                        f"{self.target_url}{endpoint}",
                        method,
                        data=data
                    )

                    if self._is_sqli_response(response):
                        evidence = response.text[:200] if response else ""
                        results["vulnerabilities"].append(self._validate_vulnerability_entry({
                            "type": "SQLi",
                            "parameter": param,
                            "payload": payload,
                            "evidence": evidence,
                            "endpoint": f"{method} {endpoint}"
                        }))
                        results["vulnerable"] = True
                except Exception as e:
                    logger.error(f"SQLi test failed: {str(e)}")
        return results

    def check_csrf(self):
        """CSRF detection with modern protection checks"""
        results = {
            "vulnerable": False,
            "forms": []
        }
        endpoints = [
            ("/profile", ["username", "email"]),
            ("/api/BasketItems", ["ProductId"]),
            ("/rest/user/change-password", ["current", "new", "repeat"])
        ]

        for endpoint, params in endpoints:
            response = self._make_request(f"{self.target_url}{endpoint}")
            if not response:
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form')
            if form and not form.find('input', {'name': ['_csrf', 'csrfToken']}):
                results["vulnerable"] = True
                for param in params:
                    results["forms"].append(self._validate_vulnerability_entry({
                        "type": "CSRF",
                        "parameter": param,
                        "endpoint": endpoint,
                        "form_action": form.get('action', '#'),
                        "protection": "Missing CSRF token"
                    }))
        return results

    def run_scan(self, options: Dict) -> Dict:
        """Main scanning controller with proper progress tracking"""
        enabled_scans = [scan for scan, enabled in options.items() if enabled]
        self.progress = tqdm(total=len(enabled_scans) * 100, desc="Scanning Progress")

        results = {
            "target": self.target_url,
            "results": {
                "xss": [],
                "sqli": {"vulnerable": False, "vulnerabilities": []},
                "csrf": {"vulnerable": False, "forms": []}
            },
            "status": "COMPLETED"
        }

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                if options.get('xss'):
                    futures.append(executor.submit(self.test_xss))
                if options.get('sqli'):
                    futures.append(executor.submit(self.test_sqli))
                if options.get('csrf'):
                    futures.append(executor.submit(self.check_csrf))

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    self.progress.update(100)

                    if isinstance(result, list):  # XSS results
                        results["results"]["xss"] = result
                    elif "forms" in result:  # CSRF results
                        results["results"]["csrf"] = result
                    else:  # SQLi results
                        results["results"]["sqli"] = result

            # Generate summary
            results["summary"] = {
                "xss_count": len(results["results"]["xss"]),
                "sqli_vulnerabilities": len(results["results"]["sqli"]["vulnerabilities"]),
                "csrf_forms": len(results["results"]["csrf"]["forms"])
            }

        except Exception as e:
            results["status"] = "FAILED"
            results["error"] = str(e)
        finally:
            self.progress.close()

        return results
