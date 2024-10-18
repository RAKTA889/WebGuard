# WebGuard - Vulnerability Scanner

__          ________ ____   _____ _    _         _____  _____  
\ \        / /  ____|  _ \ / ____| |  | |  /\   |  __ \|  __ \ 
 \ \  /\  / /| |__  | |_) | |  __| |  | | /  \  | |__) | |  | |
  \ \/  \/ / |  __| |  _ <| | |_ | |  | |/ /\ \ |  _  /| |  | |
   \  /\  /  | |____| |_) | |__| | |__| / ____ \| | \ \| |__| |
    \/  \/   |______|____/ \_____|\____/_/    \_\_|  \_\_____/ 
                                                                

**WebGuard** is an advanced vulnerability scanner that focuses on detecting common security flaws in web applications, such as **XSS (Cross-Site Scripting)**, **SQL Injection**, **Directory Traversal**, and **CSRF (Cross-Site Request Forgery)**.

This project aims to automate the identification of security vulnerabilities to make web applications safer for end-users and easier for developers to audit.

## Features
- **XSS (Cross-Site Scripting) Detection**: Detects and reports potential XSS vulnerabilities.
- **SQL Injection Detection**: Scans for SQL injection vulnerabilities in web forms.
- **Directory Traversal**: Identifies directory traversal vulnerabilities that may expose sensitive files.
- **CSRF (Cross-Site Request Forgery)**: Detects potential CSRF vulnerabilities to prevent unauthorized actions.
- **DOM-based XSS Detection**: Scans for client-side vulnerabilities in web applications.

## Technologies
- **Python**: The primary language used to build this tool.
- **Selenium**: Used for simulating browser interaction and automating tests for XSS, SQLi, etc.
- **Requests**: For sending HTTP requests and analyzing responses.
- **Git**: Version control for tracking changes in the project.
- **Webdriver Manager**: To handle browser drivers (ChromeDriver).

## Installation
### Requirements:
- Python 3.6 or higher
- Pip (Python package manager)
