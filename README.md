# Automated-Web-Scanner
A python-based web scanner that checks website security headers and basic CORS configurations for potential security concerns. It identifies missing or misconfigured security headers, analyzes CORS settings, and helps developers understand common web security issues using python and HTTP response analysis 
**Project Overview**
Automated Web Scanner is an educational Python project that checks a website's HTTP response for selected security headers and basic Cross-Origin Resource Sharing (CORS) configuration patterns that may need manual review.
**Objectives**
.Check whether selected HTTP security headers are present.
.Display the values of headers that are present.
.Send an OPTIONS request using a reserved test origin and inspect the CORS response headers.
.Report potential configuration concerns for manual verification.
**Technologies Used**
.Python 3
.Requests library
**Project Files**
.web_scanner.py — Python script that performs the audit.
.requirements.txt — Lists the Python dependency required by the script.
.README.md — Project overview and instructions.
**Setup**
1.Install Python 3.
2.Download or clone this repository.
3.Open a terminal in the project folder.
4.Install the required dependency:
    python -m pip install -r requirements.txt
**Run the Scanner**
Run the scanner against a website that you own or have explicit permission to test:
    python web_scanner.py https://example.com
Replace https://example.com with your authorized test target.
To save the results as a JSON report:
    python web_scanner.py https://example.com --json report.json
You can change the request timeout (in seconds) with --timeout:
    python web_scanner.py https://example.com --timeout 15
**What It Checks**
**Security Headers**
The scanner checks whether these response headers are present:
.Strict-Transport-Security
.Content-Security-Policy
.X-Content-Type-Options
.Referrer-Policy
.Permissions-Policy
.X-Frame-Options
.It reports missing headers and displays available header values.
**CORS**
The scanner sends an OPTIONS request with the reserved test origin https://cors-audit.invalid and inspects response headers such as:
.Access-Control-Allow-Origin
.Access-Control-Allow-Credentials
.Access-Control-Allow-Methods
.Access-Control-Allow-Headers
It reports patterns such as a wildcard origin or reflection of the test origin. These observations are indicators for manual review, not proof that a vulnerability is exploitable.
**Output**
The script prints a readable summary in the terminal. If the --json option is supplied, it also saves the full results to the specified JSON file.
**Limitations**
.A missing header is not automatically proof of a vulnerability.
.CORS behavior can vary by endpoint, request method, authentication state, and application design.
.Some servers may handle OPTIONS requests differently or may not support them.
.This is a basic educational checker, not a comprehensive penetration test or security certification.
.The scanner does not crawl a website or test authenticated application workflows.
.Findings should be manually verified before drawing security conclusions.
**Dataset**
No external dataset is required. The scanner analyzes HTTP responses from the URL supplied by the user.

