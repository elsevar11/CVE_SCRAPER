CVE Scraper Tool
A Python command-line tool designed to scrape and compile detailed information about CVEs (Common Vulnerabilities and Exposures). It retrieves data from the MITRE API, NVD (National Vulnerability Database), and Exploit-DB, then exports reports in multiple formats including JSON, CSV, HTML, PDF, Markdown, and plain text.

Description
This project automates the process of gathering CVE details, such as CVSS scores, affected assets, available exploits, and reference links. It leverages Selenium for dynamic page loading, BeautifulSoup for HTML parsing, and fpdf for generating PDF reports. The tool is especially useful for security teams and researchers who need to quickly assess vulnerability data in a structured report.

Dependencies
Python 3.x
requests
beautifulsoup4
selenium
fpdf (fpdf2)
Google Chrome (or a compatible Chromium-based browser)
ChromeDriver (must be installed and in your system’s PATH)

Installation

Use pip to install the required packages:

pip install requests beautifulsoup4 selenium fpdf
or
pip install -r requirements.txt

Install ChromeDriver:

Download ChromeDriver from here that matches your Chrome version.
Ensure the executable is in your system’s PATH or update the code to point to its location.

Usage

Run the tool using the following command:


python main.py
When running the tool, you will be prompted for:
CVE IDs:
Enter one CVE ID. For example:
CVE-2017-0144

Output Format:
Choose from json, html, pdf, md (Markdown), or txt (plain text).

Output File Name:
Enter a base file name (without extension). Reports will be saved in the cve_reports directory.

The tool will:

Validate the CVE ID format.
Check the CVE state using the MITRE API.
Scrape detailed vulnerability data from NVD.
Retrieve affected assets from MITRE CVE API.
Scrape available exploits from Exploit-DB.
Extract and open up to 5 reference links in your default web browser.
Export a comprehensive report in your chosen format.

Additional Instructions
PDF Export:
This version uses the fpdf library to generate PDF reports. No additional configuration is needed.

Reference Links:
The tool will open up to 5 unique reference links.It opens the links as they appear on the NVD page.

Dynamic Content:
Selenium is used to load pages with dynamic content (such as NVD details and Exploit-DB results). Ensure that ChromeDriver is installed and compatible with your browser.
