# 🛡️ SchwiftyScanner  
**Automated Web Vulnerability Scanner for XSS, SQLi, and CSRF**  


[![Python Version](https://img.shields.io/badge/Python-3.10%2B-yellowgreen)](https://www.python.org/)  

A lightweight penetration testing tool to detect common web vulnerabilities (**XSS**, **SQL Injection**, **CSRF**) and empower developers to secure their applications.  

![SchwiftyScanner Logo](
rick-sanchez-schwifty-dope-laptop-exwtrlg412wnlvmw.jpg) 

---

## ✨ Features  
- **XSS Detection**: Scans for reflected and stored Cross-Site Scripting vulnerabilities.  
- **SQLi Exploitation**: Tests for SQL injection flaws using error-based and time-based techniques.  
- **CSRF Token Check**: Identifies forms missing anti-CSRF tokens.  
- **Browser Automation**: Uses Selenium for dynamic payload testing.  
- **Custom Payloads**: Supports a wide range of obfuscated and WAF-bypass payloads.  

---

## 🚀 Installation  
```bash  
git clone https://github.com/xmr-gif/Schwifty-Scanner.git 
cd Schwifty-Scanner  
pip3 install -r requirements.txt

python3 -m venv penv
source penv/bin/activate

```
---

## 🔧 Options

**-u URL :** 	Target URL to scan
**-xss**	Enable XSS detection
**-sqli**	Enable SQL injection checks
**-csrf**	Check for missing CSRF tokens
**-v**	Verbose mode (show detailed logs)
**-o** FILE	Save results to a file

## 🛠️ Usage
```bash  
python3 schwifty.py -u <TARGET_URL> [OPTIONS]  

# Example:  
python3 schwifty.py -u https://juice-shop.herokuapp.com -xss -sqli -v -o report.txt  

