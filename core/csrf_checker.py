from bs4 import BeautifulSoup
def check_csrf(self):
    """CSRF check with parameter identification"""
    csrf_points = [
        {"url": "/profile", "method": "PUT", "params": ["username", "email"]},
        {"url": "/api/BasketItems", "method": "POST", "params": ["ProductId", "quantity"]},
        {"url": "/rest/user/change-password", "method": "POST", "params": ["current", "new", "repeat"]}
    ]

    results = {
        "vulnerable": False,
        "vulnerable_endpoints": []
    }

    for point in csrf_points:
        full_url = f"{self.target_url}{point['url']}"
        response = self._make_request(full_url)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form', {'method': point['method']})

            if form:
                missing_protection = []
                for param in point["params"]:
                    if not form.find('input', {'name': param}):
                        missing_protection.append(param)

                if missing_protection:
                    results["vulnerable"] = True
                    results["vulnerable_endpoints"].append({
                        "endpoint": f"{point['method']} {point['url']}",
                        "vulnerable_parameters": missing_protection,
                        "form_action": form.get('action'),
                        "protection_status": "Missing CSRF token"
                    })

    return results