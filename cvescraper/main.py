import requests
from bs4 import BeautifulSoup
import json
import time
import re
from datetime import datetime
import os
import webbrowser
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from fpdf import FPDF  
def setup_chrome_options():
    options = Options()
    options.add_argument("--headless")             
    options.add_argument("--disable-gpu")         
    options.add_argument("--disable-extensions")   
    options.add_argument("--blink-settings=imagesEnabled=false")  
    options.add_argument("--disable-notifications")  
    options.add_argument("--log-level=3")          
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.add_argument("--incognito")            
    return options

driver = webdriver.Chrome(options=setup_chrome_options())

# ---------- Base URLs and Regex ----------
NVD_BASE_URL = "https://nvd.nist.gov/vuln/detail/"
MITRE_API_URL = "https://cveawg.mitre.org/api/cve-id/"
MITRE_CVE_API_URL = "https://cveawg.mitre.org/api/cve/"
EXPLOIT_DB_URL = "https://www.exploit-db.com/search"
CVE_REGEX = r"CVE-(1999|20[0-1][0-9]|20[0-2][0-4])-(\d{4,})"

# ---------- Exploit Data ----------
def fetch_exploit_data(cve_id):
    """Scrape exploit data from Exploit-DB for the given CVE ID."""
    print(f"Searching for exploits for {cve_id} on Exploit-DB...")
    url = f"{EXPLOIT_DB_URL}?cve={cve_id}&verified=true"
    exploit_data_list = []
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "exploits-table"))
        )
        time.sleep(2)  # Wait for table to load fully
        try:
            no_results = driver.find_element(By.XPATH, "//td[contains(text(), 'No matching records found')]")
            if no_results:
                print("No exploits found on Exploit-DB for this CVE.")
                return []
        except NoSuchElementException:
            pass
        page_num = 1
        while True:
            print(f"Processing exploit results page {page_num}...")
            rows = driver.find_elements(By.XPATH, "//table[@id='exploits-table']/tbody/tr")
            if not rows:
                break
            for row in rows:
                try:
                    title_elem = row.find_element(By.XPATH, ".//td[5]/a")
                    title = title_elem.text.strip()
                    title_link = title_elem.get_attribute('href')
                    date = row.find_element(By.XPATH, ".//td[1]").text.strip()
                    exploit_type = row.find_element(By.XPATH, ".//td[6]").text.strip()
                    platform = row.find_element(By.XPATH, ".//td[7]").text.strip()
                    author = row.find_element(By.XPATH, ".//td[8]").text.strip()
                    try:
                        download_link = row.find_element(By.XPATH, ".//td[2]/a").get_attribute('href')
                    except NoSuchElementException:
                        download_link = "N/A"
                    exploit_data = {
                        "title": title,
                        "title_link": title_link,
                        "date": date,
                        "type": exploit_type,
                        "platform": platform,
                        "author": author,
                        "download_link": download_link
                    }
                    exploit_data_list.append(exploit_data)
                   
                except Exception as e:
                    print(f"Error processing exploit row: {e}")
                    continue
            try:
                next_button = driver.find_element(By.XPATH, "//li[@class='next']/a")
                if 'disabled' in next_button.get_attribute('class'):
                    break
                next_button.click()
                page_num += 1
                time.sleep(2)
            except NoSuchElementException:
                break
    except Exception as e:
        print(f"Error fetching exploit data: {e}")
        return []
    print(f"Found {len(exploit_data_list)} exploits for {cve_id}")
    return exploit_data_list

# ---------- CVE Data Functions ----------
def get_cve_state(cve_id):
    """Fetch the CVE state from the MITRE API."""
    url = f"{MITRE_API_URL}{cve_id}"
    try:
        resp = requests.get(url)
        time.sleep(1)
        if resp.status_code == 200:
            return resp.json(), True
        else:
            print(f"Error: MITRE API request failed for {cve_id} (Status: {resp.status_code})")
            return None, False
    except requests.exceptions.RequestException as e:
        print(f"Error: RequestException for MITRE API for {cve_id}: {e}")
        return None, False

def fetch_cve_details(cve_id):
    """Fetch affected assets from the MITRE CVE API."""
    url = f"{MITRE_CVE_API_URL}{cve_id}"
    try:
        resp = requests.get(url)
        time.sleep(1)
        if resp.status_code == 200:
            data = resp.json()
            assets = []
            if "containers" in data and "cna" in data["containers"]:
                for item in data["containers"]["cna"].get("affected", []):
                    vendor = item.get("vendor", "Unknown Vendor")
                    product = item.get("product", "Unknown Product")
                    assets.append((vendor, product))
            return assets
        else:
            print(f"Error: MITRE CVE API request failed for {cve_id} (Status: {resp.status_code})")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error: RequestException for MITRE CVE API for {cve_id}: {e}")
        return None

def fetch_cve_page(cve_id):
    """Use Selenium to load the NVD CVE page and return its HTML source."""
    url = f"{NVD_BASE_URL}{cve_id}"
    try:
        driver.get(url)
        time.sleep(3)
        return driver.page_source
    except Exception as e:
        print(f"Error loading page for {cve_id}: {e}")
        return None

def extract_cve_details(html_content):
    """Extract CVE details from the NVD HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    cve_id_elem = soup.find('span', {'data-testid': 'page-header-vuln-id'})
    cve_id = cve_id_elem.text.strip() if cve_id_elem else 'N/A'
    
    desc_elem = soup.find('p', {'data-testid': 'vuln-description'})
    description = desc_elem.text.strip() if desc_elem else 'N/A'
    
    cvss_v3_elem = soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})
    cvss_v3_score = cvss_v3_elem.text.strip() if cvss_v3_elem else 'N/A'
    cvss_v3_vector_elem = soup.find('span', {'class': 'tooltipCvss3NistMetrics'})
    cvss_v3_vector = cvss_v3_vector_elem.text.strip() if cvss_v3_vector_elem else 'N/A'
    
    cvss_v2_elem = soup.find('a', {'id': 'Cvss2CalculatorAnchor'})
    cvss_v2_score = cvss_v2_elem.text.strip() if cvss_v2_elem else 'N/A'
    cvss_v2_vector_elem = soup.find('span', {'class': 'tooltipCvss2NistMetrics'})
    cvss_v2_vector = cvss_v2_vector_elem.text.strip() if cvss_v2_vector_elem else 'N/A'
    
    if cvss_v3_score.lower() != 'n/a':
        final_score = cvss_v3_score
        final_vector = cvss_v3_vector
        score_version = "CVSS 3.0"
    elif cvss_v2_score.lower() != 'n/a':
        final_score = cvss_v2_score
        final_vector = cvss_v2_vector
        score_version = "CVSS 2.0"
    else:
        final_score = 'N/A'
        final_vector = 'N/A'
        score_version = "N/A"
    
    severity = "N/A"
    try:
        score_float = float(final_score.split()[0])
        if score_float >= 9.0:
            severity = "CRITICAL"
        elif score_float >= 7.0:
            severity = "HIGH"
        elif score_float >= 4.0:
            severity = "MEDIUM"
        elif score_float > 0:
            severity = "LOW"
        else:
            severity = "NONE"
    except (ValueError, IndexError):
        pass
    
    return {
        "CVE_ID": cve_id,
        "Description": description,
        "CVSS_Score": final_score,
        "CVSS_Vector": final_vector,
        "CVSS_Version": score_version,
        "Severity": severity
    }

def extract_references(html_content):
    """Extract reference URLs from the NVD page (panel or table)."""
    soup = BeautifulSoup(html_content, 'html.parser')
    references = []
    
    panel = soup.find("div", id="vulnHyperlinksPanel")
    if panel:
        for a in panel.find_all("a", href=True):
            references.append(a["href"])
    
    if not references:
        rows = soup.find_all("tr", attrs={"data-testid": re.compile(r"vuln-hyperlinks-row-\d+")})
        for row in rows:
            a_tag = row.find("a", attrs={"data-testid": re.compile(r"vuln-hyperlinks-link-\d+")})
            if a_tag and a_tag.get("href"):
                references.append(a_tag["href"])
    return references

def validate_cve_id_format(cve_id):
    """Regex-based CVE ID validation."""
    cve_id = cve_id.strip().upper()
    match = re.match(CVE_REGEX, cve_id)
    if match:
        year = int(match.group(1))
        id_part = match.group(2)
        now = datetime.now().year
        if year < 1999 or year > now:
            return False, "Invalid year range. Year must be between 1999 and current year."
        if len(id_part) < 4 or id_part == "0000":
            return False, "Invalid CVE ID. ID must be 4+ digits and cannot be all zeros."
        return True, cve_id
    else:
        return False, "Invalid CVE format. Must be 'CVE-YYYY-XXXX'."

# ---------- Save Functions ----------
def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"Data saved to {filename}")

def save_to_html(data, filename):
    """
    Updated function that shows each exploit in its own row in the "AVAILABLE EXPLOITS" table.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            severity_color = "#FFFFFF"
            if data.get("Severity") == "CRITICAL":
                severity_color = "#CC0000"
            elif data.get("Severity") == "HIGH":
                severity_color = "#FF0000"
            elif data.get("Severity") == "MEDIUM":
                severity_color = "#FFA500"
            elif data.get("Severity") == "LOW":
                severity_color = "#FFFF00"
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{data.get("CVE_ID", "CVE Details")}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #1E1E1E;
            color: #FFFFFF;
            margin: 0;
            padding: 20px;
        }}
        .cve-container {{
            max-width: 800px;
            margin: 0 auto;
            background-color: #2D2D2D;
            border-radius: 5px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        }}
        .cve-header {{
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 15px;
        }}
        .score-container {{
            margin-bottom: 20px;
        }}
        .cvss-score {{
            font-size: 28px;
            font-weight: bold;
            color: {severity_color};
            margin-bottom: 15px;
        }}
        .severity {{
            margin-top: 5px;
            margin-bottom: 15px;
            font-weight: bold;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: bold;
            margin-top: 20px;
            margin-bottom: 14px;
            color: #CCCCCC;
        }}
        .section-content {{
            margin-left: 0px;
            line-height: 1.5;
        }}
        .vector-string {{
            font-size: 16px;
            font-family: monospace;
            background-color: #3E3E3E;
            margin: 10px 0 0 0;
            padding: 5px 6px;
            border-radius: 3px;
            display: inline-block;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #444444;
        }}
        th {{
            background-color: #3E3E3E;
            color: #CCCCCC;
        }}
        .status-message {{
            background-color: #3E3E3E;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            text-align: center;
            font-weight: bold;
        }}
        /* Table styling for the Exploit section */
        .exploits-table td a {{
            color: #6699CC;
            text-decoration: none;
        }}
        .exploits-table td a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="cve-container">
        <div class="cve-header">{data.get("CVE_ID", "Unknown CVE")}</div>
"""

            status = data.get("Status", "").upper()
            if status in ["RESERVED", "REJECTED", "INVALID", "NOT_FOUND"]:
                # If the CVE is in a special state, show a status message only
                html_content += f"""
        <div class="status-message">
            {data.get("Description", "No details available.")}
        </div>
"""
            else:
                # Normal CVE details
                html_content += f"""
        <div class="score-container">
            <div class="cvss-score">{data.get("CVSS_Score", "N/A")}</div>
            <div>CVSS SCORE - {data.get("CVSS_Version", "")}</div>
            <div class="vector-string">{data.get("CVSS_Vector", "N/A")}</div>
        </div>
        <div class="section-title">DESCRIPTION</div>
        <div class="section-content">
            {data.get("Description", "N/A")}
        </div>
        <div class="section-title">AFFECTED ASSETS</div>
        <div class="section-content">
            <table>
                <thead>
                    <tr><th>VENDOR</th><th>PRODUCT</th></tr>
                </thead>
                <tbody>
"""
                assets = data.get("Affected_Assets", [])
                if assets:
                    for vendor, product in assets:
                        html_content += f"""
                    <tr>
                        <td>{vendor}</td>
                        <td>{product}</td>
                    </tr>
"""
                else:
                    html_content += """
                    <tr><td colspan="2">No affected assets found.</td></tr>
"""
                html_content += """
                </tbody>
            </table>
        </div>
"""

                # ==============
                # AVAILABLE EXPLOITS
                # ==============
                exploits = data.get("Exploits", [])
                html_content += """
        <div class="section-title">AVAILABLE EXPLOITS</div>
        <div class="section-content">
"""
                if exploits:
                    html_content += """
            <table class="exploits-table">
                <thead>
                    <tr>
                        <th>VALID LINKS</th>
                    </tr>
                </thead>
                <tbody>
"""
                    for exploit in exploits:
                       # title = exploit.get("title", "Unnamed Exploit")
                        link = exploit.get("title_link", "#")
                        html_content += f"""
                    <tr>
                       
                        <td><a href="{link}" target="_blank">{link}</a></td>
                    </tr>
"""
                    html_content += """
                </tbody>
            </table>
"""
                else:
                    html_content += """
            <div class="status-message">No public exploits found for this CVE.</div>
"""
                html_content += """
        </div>
"""

            # End main container
            html_content += """
    </div>
</body>
</html>
"""
            f.write(html_content)
            print(f"HTML report saved to {filename}")
    except Exception as e:
        print(f"Error saving HTML: {e}")

def save_to_pdf(data, filename):
    """Generate PDF report using fpdf."""
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, txt=data.get("CVE_ID", "Unknown CVE"), ln=True, align="C")
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, txt=f"Status: {data.get('Status', 'N/A')}", ln=True)
        pdf.ln(5)
        pdf.cell(0, 10, txt="Description:", ln=True)
        pdf.multi_cell(0, 10, txt=data.get("Description", "N/A"))
        pdf.ln(5)
        pdf.cell(0, 10, txt=f"CVSS Score: {data.get('CVSS_Score', 'N/A')} ({data.get('CVSS_Version', 'N/A')})", ln=True)
        pdf.cell(0, 10, txt=f"CVSS Vector: {data.get('CVSS_Vector', 'N/A')}", ln=True)
        pdf.cell(0, 10, txt=f"Severity: {data.get('Severity', 'N/A')}", ln=True)
        pdf.ln(5)
        pdf.cell(0, 10, txt="Affected Assets:", ln=True)
        assets = data.get("Affected_Assets", [])
        if assets:
            for vendor, product in assets:
                pdf.cell(0, 10, txt=f"- {vendor}: {product}", ln=True)
        else:
            pdf.cell(0, 10, txt="None", ln=True)
        if data.get("Exploits"):
            pdf.ln(5)
            pdf.cell(0, 10, txt="Available Exploits:", ln=True)
            for exploit in data["Exploits"]:
                link = exploit.get("title_link", "")
                pdf.multi_cell(0, 10, txt=f"-{link}")
        pdf.output(filename)
        print(f"PDF report saved to {filename}")
    except Exception as e:
        print(f"Error saving PDF: {e}")

def save_to_md(data, filename):
    """Save report as a Markdown file."""
    try:
        md_content = f"# CVE Report: {data.get('CVE_ID', 'Unknown CVE')}\n\n"
        md_content += f"**Status:** {data.get('Status', 'N/A')}\n\n"
        md_content += "## Description\n"
        md_content += f"{data.get('Description', 'N/A')}\n\n"
        md_content += "## CVSS Metrics\n"
        md_content += f"- **Score:** {data.get('CVSS_Score', 'N/A')} ({data.get('CVSS_Version', 'N/A')})\n"
        md_content += f"- **Vector:** `{data.get('CVSS_Vector', 'N/A')}`\n"
        md_content += f"- **Severity:** {data.get('Severity', 'N/A')}\n\n"
        md_content += "## Affected Assets\n"
        assets = data.get("Affected_Assets", [])
        if assets:
            for vendor, product in assets:
                md_content += f"- **Vendor:** {vendor} | **Product:** {product}\n"
        else:
            md_content += "No affected assets found.\n\n"
        if data.get("Exploits"):
            md_content += "\n## Available Exploits\n"
            for exploit in data["Exploits"]:
                md_content += f"- ({exploit.get('title_link', '#')})\n"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {filename}")
    except Exception as e:
        print(f"Error saving Markdown: {e}")

def save_to_txt(data, filename):
    """Save report as a plain text file."""
    try:
        txt_content = f"CVE Report: {data.get('CVE_ID', 'Unknown CVE')}\n"
        txt_content += f"Status: {data.get('Status', 'N/A')}\n\n"
        txt_content += "Description:\n"
        txt_content += f"{data.get('Description', 'N/A')}\n\n"
        txt_content += "CVSS Metrics:\n"
        txt_content += f"  Score: {data.get('CVSS_Score', 'N/A')} ({data.get('CVSS_Version', 'N/A')})\n"
        txt_content += f"  Vector: {data.get('CVSS_Vector', 'N/A')}\n"
        txt_content += f"  Severity: {data.get('Severity', 'N/A')}\n\n"
        txt_content += "Affected Assets:\n"
        assets = data.get("Affected_Assets", [])
        if assets:
            for vendor, product in assets:
                txt_content += f"  - Vendor: {vendor}, Product: {product}\n"
        else:
            txt_content += "  No affected assets found.\n"
        if data.get("Exploits"):
            txt_content += "\nAvailable Exploits:\n"
            for exploit in data["Exploits"]:
                txt_content += f"-({exploit.get('title_link', '#')})\n"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(txt_content)
        print(f"Text report saved to {filename}")
    except Exception as e:
        print(f"Error saving Text file: {e}")

def process_cve_id(cve_id, output_format, output_filename):
    valid, info = validate_cve_id_format(cve_id)
    if not valid:
        print(f"Invalid CVE ID format: {cve_id} - {info}")
        invalid_data = {
            "CVE_ID": cve_id,
            "Status": "INVALID",
            "Description": info,
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(invalid_data, output_filename)
        elif output_format == "csv":
            save_to_csv(invalid_data, output_filename)
        elif output_format == "html":
            save_to_html(invalid_data, output_filename)
        elif output_format == "pdf":
            save_to_pdf(invalid_data, output_filename)
        elif output_format == "md":
            save_to_md(invalid_data, output_filename)
        elif output_format == "txt":
            save_to_txt(invalid_data, output_filename)
        return
    
    cve_id = info
    print(f"CVE ID format is valid: {cve_id}")
    print("Checking if the CVE ID exists in the MITRE database...\n")
    
    data, exists = get_cve_state(cve_id)
    if not exists:
        print("This CVE ID does not exist in the MITRE database or could not be retrieved.\n")
        notfound_data = {
            "CVE_ID": cve_id,
            "Status": "NOT_FOUND",
            "Description": "CVE ID has valid format but not found in MITRE database.",
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(notfound_data, output_filename)
        elif output_format == "csv":
            save_to_csv(notfound_data, output_filename)
        elif output_format == "html":
            save_to_html(notfound_data, output_filename)
        elif output_format == "pdf":
            save_to_pdf(notfound_data, output_filename)
        elif output_format == "md":
            save_to_md(notfound_data, output_filename)
        elif output_format == "txt":
            save_to_txt(notfound_data, output_filename)
        return
    
    print("MITRE API Data:")
    for k, v in data.items():
        print(f"{k}: {v}")
    
    state = data.get("state", "N/A")
    if state in ["RESERVED", "REJECTED"]:
        print(f"\nCVE {cve_id} is {state}. Creating a simplified report.\n")
        simplified = {
            "CVE_ID": cve_id,
            "Status": state,
            "Description": f"This CVE is {state}.",
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(simplified, output_filename)
        elif output_format == "csv":
            save_to_csv(simplified, output_filename)
        elif output_format == "html":
            save_to_html(simplified, output_filename)
        elif output_format == "pdf":
            save_to_pdf(simplified, output_filename)
        elif output_format == "md":
            save_to_md(simplified, output_filename)
        elif output_format == "txt":
            save_to_txt(simplified, output_filename)
        return
    
    print(f"\nCVE {cve_id} is {state}. Proceeding with NVD extraction...\n")
    
    print("Fetching affected assets from MITRE CVE API...")
    assets = fetch_cve_details(cve_id)
    
    html_content = fetch_cve_page(cve_id)
    if not html_content:
        print("No valid data from NVD. Check the CVE ID and try again.")
        basic_data = {
            "CVE_ID": cve_id,
            "Status": state,
            "Description": "Could not retrieve from NVD.",
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(basic_data, output_filename)
        elif output_format == "csv":
            save_to_csv(basic_data, output_filename)
        elif output_format == "html":
            save_to_html(basic_data, output_filename)
        elif output_format == "pdf":
            save_to_pdf(basic_data, output_filename)
        elif output_format == "md":
            save_to_md(basic_data, output_filename)
        elif output_format == "txt":
            save_to_txt(basic_data, output_filename)
        return
    
    cve_data = extract_cve_details(html_content)
    cve_data["Status"] = state
    cve_data["Affected_Assets"] = assets if assets else []
    
    if assets:
        print("\nAffected Assets:")
        for vendor, product in assets:
            print(f"Vendor: {vendor} | Product: {product}")
    else:
        print("\nNo affected assets found.")
    
    print("\nExtracted CVE Details:")
    for key, val in cve_data.items():
        if key != "Affected_Assets":
            print(f"{key}: {val}")
    
    print("\nSearching for available exploits...")
    exploits = fetch_exploit_data(cve_id)
    cve_data["Exploits"] = exploits if exploits else []
    if exploits:
        print(f"\nFound {len(exploits)} exploits:")
        for i, exploit in enumerate(exploits, 1):
            print(f"{i}. {exploit.get('title', 'Unnamed Exploit')}")
    else:
        print("\nNo public exploits found.")
    
    references = extract_references(html_content)
    if references:
        filtered = []
        for ref in references:
            ref_lower = ref.lower()
            if ref_lower.startswith("mailto:"):
                continue
            if "packetstormsecurity.com" in ref_lower:
                continue
            if "securityfocus.com" in ref_lower:
                continue
            if "securitytracker.com" in ref_lower:
                continue
            if not (ref_lower.startswith("http://") or ref_lower.startswith("https://")):
                continue
            filtered.append(ref)
        
        seen = set()
        unique_refs = []
        for r in filtered:
            normalized = r.rstrip('/')
            if normalized not in seen:
                seen.add(normalized)
                unique_refs.append(r)
        
        if unique_refs:
            print("\nOpening up to 5 references in the web browser (no connectivity check):")
            count = 0
            for link in unique_refs:
                if count >= 5:
                    break
                print(link)
                webbrowser.open(link)
                time.sleep(0.5)
                count += 1
        else:
            print("No valid references after filtering.")
    else:
        print("No references found on the page.")
    
    if output_format == "json":
        save_to_json(cve_data, output_filename)
    elif output_format == "csv":
        save_to_csv(cve_data, output_filename)
    elif output_format == "html":
        save_to_html(cve_data, output_filename)
    elif output_format == "pdf":
        save_to_pdf(cve_data, output_filename)
    elif output_format == "md":
        save_to_md(cve_data, output_filename)
    elif output_format == "txt":
        save_to_txt(cve_data, output_filename)
    
    return output_format in ["html", "pdf", "md", "txt"] and os.path.exists(output_filename)

def save_to_md(data, filename):
    """Save report as a Markdown file."""
    try:
        md_content = f"# CVE Report: {data.get('CVE_ID', 'Unknown CVE')}\n\n"
        md_content += f"**Status:** {data.get('Status', 'N/A')}\n\n"
        md_content += "## Description\n"
        md_content += f"{data.get('Description', 'N/A')}\n\n"
        md_content += "## CVSS Metrics\n"
        md_content += f"- **Score:** {data.get('CVSS_Score', 'N/A')} ({data.get('CVSS_Version', 'N/A')})\n"
        md_content += f"- **Vector:** `{data.get('CVSS_Vector', 'N/A')}`\n"
        md_content += f"- **Severity:** {data.get('Severity', 'N/A')}\n\n"
        md_content += "## Affected Assets\n"
        assets = data.get("Affected_Assets", [])
        if assets:
            for vendor, product in assets:
                md_content += f"- **Vendor:** {vendor} | **Product:** {product}\n"
        else:
            md_content += "No affected assets found.\n\n"
        if data.get("Exploits"):
            md_content += "\n## Available Exploits\n"
            for exploit in data["Exploits"]:
                md_content += f"- [{exploit.get('title', 'Unnamed Exploit')}]({exploit.get('title_link', '#')})\n"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {filename}")
    except Exception as e:
        print(f"Error saving Markdown: {e}")

def save_to_txt(data, filename):
    """Save report as a plain text file."""
    try:
        txt_content = f"CVE Report: {data.get('CVE_ID', 'Unknown CVE')}\n"
        txt_content += f"Status: {data.get('Status', 'N/A')}\n\n"
        txt_content += "Description:\n"
        txt_content += f"{data.get('Description', 'N/A')}\n\n"
        txt_content += "CVSS Metrics:\n"
        txt_content += f"  Score: {data.get('CVSS_Score', 'N/A')} ({data.get('CVSS_Version', 'N/A')})\n"
        txt_content += f"  Vector: {data.get('CVSS_Vector', 'N/A')}\n"
        txt_content += f"  Severity: {data.get('Severity', 'N/A')}\n\n"
        txt_content += "Affected Assets:\n"
        assets = data.get("Affected_Assets", [])
        if assets:
            for vendor, product in assets:
                txt_content += f"  - Vendor: {vendor}, Product: {product}\n"
        else:
            txt_content += "  No affected assets found.\n"
        if data.get("Exploits"):
            txt_content += "\nAvailable Exploits:\n"
            for exploit in data["Exploits"]:
                txt_content += f"  -({exploit.get('title_link', '#')})\n"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(txt_content)
        print(f"Text report saved to {filename}")
    except Exception as e:
        print(f"Error saving Text file: {e}")

def process_cve_id(cve_id, output_format, output_filename):
    valid, info = validate_cve_id_format(cve_id)
    if not valid:
        print(f"Invalid CVE ID format: {cve_id} - {info}")
        invalid_data = {
            "CVE_ID": cve_id,
            "Status": "INVALID",
            "Description": info,
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(invalid_data, output_filename)
        elif output_format == "csv":
            save_to_csv(invalid_data, output_filename)
        elif output_format == "html":
            save_to_html(invalid_data, output_filename)
        elif output_format == "pdf":
            save_to_pdf(invalid_data, output_filename)
        elif output_format == "md":
            save_to_md(invalid_data, output_filename)
        elif output_format == "txt":
            save_to_txt(invalid_data, output_filename)
        return
    
    cve_id = info
    print(f"CVE ID format is valid: {cve_id}")
    print("Checking if the CVE ID exists in the MITRE database...\n")
    
    data, exists = get_cve_state(cve_id)
    if not exists:
        print("This CVE ID does not exist in the MITRE database or could not be retrieved.\n")
        notfound_data = {
            "CVE_ID": cve_id,
            "Status": "NOT_FOUND",
            "Description": "CVE ID has valid format but not found in MITRE database.",
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(notfound_data, output_filename)
        elif output_format == "csv":
            save_to_csv(notfound_data, output_filename)
        elif output_format == "html":
            save_to_html(notfound_data, output_filename)
        elif output_format == "pdf":
            save_to_pdf(notfound_data, output_filename)
        elif output_format == "md":
            save_to_md(notfound_data, output_filename)
        elif output_format == "txt":
            save_to_txt(notfound_data, output_filename)
        return
    
    print("MITRE API Data:")
    for k, v in data.items():
        print(f"{k}: {v}")
    
    state = data.get("state", "N/A")
    if state in ["RESERVED", "REJECTED"]:
        print(f"\nCVE {cve_id} is {state}. Creating a simplified report.\n")
        simplified = {
            "CVE_ID": cve_id,
            "Status": state,
            "Description": f"This CVE is {state}.",
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(simplified, output_filename)
        elif output_format == "csv":
            save_to_csv(simplified, output_filename)
        elif output_format == "html":
            save_to_html(simplified, output_filename)
        elif output_format == "pdf":
            save_to_pdf(simplified, output_filename)
        elif output_format == "md":
            save_to_md(simplified, output_filename)
        elif output_format == "txt":
            save_to_txt(simplified, output_filename)
        return
    
    print(f"\nCVE {cve_id} is {state}. Proceeding with NVD extraction...\n")
    
    print("Fetching affected assets from MITRE CVE API...")
    assets = fetch_cve_details(cve_id)
    
    html_content = fetch_cve_page(cve_id)
    if not html_content:
        print("No valid data from NVD. Check the CVE ID and try again.")
        basic_data = {
            "CVE_ID": cve_id,
            "Status": state,
            "Description": "Could not retrieve from NVD.",
            "CVSS_Score": "N/A",
            "CVSS_Vector": "N/A",
            "Severity": "N/A",
            "Affected_Assets": [],
            "Exploits": []
        }
        if output_format == "json":
            save_to_json(basic_data, output_filename)
        elif output_format == "csv":
            save_to_csv(basic_data, output_filename)
        elif output_format == "html":
            save_to_html(basic_data, output_filename)
        elif output_format == "pdf":
            save_to_pdf(basic_data, output_filename)
        elif output_format == "md":
            save_to_md(basic_data, output_filename)
        elif output_format == "txt":
            save_to_txt(basic_data, output_filename)
        return
    
    cve_data = extract_cve_details(html_content)
    cve_data["Status"] = state
    cve_data["Affected_Assets"] = assets if assets else []
    
    if assets:
        print("\nAffected Assets:")
        for vendor, product in assets:
            print(f"Vendor: {vendor} | Product: {product}")
    else:
        print("\nNo affected assets found.")
    
    print("\nExtracted CVE Details:")
    for key, val in cve_data.items():
        if key != "Affected_Assets":
            print(f"{key}: {val}")
    
    print("\nSearching for available exploits...")
    exploits = fetch_exploit_data(cve_id)
    cve_data["Exploits"] = exploits if exploits else []
    if exploits:
        print(f"\nFound {len(exploits)} exploits:")
        for i, exploit in enumerate(exploits, 1):
            print(f"{i}. {exploit.get('title_link', '')}")
    else:
        print("\nNo public exploits found.")
    
    references = extract_references(html_content)
    if references:
        filtered = []
        for ref in references:
            ref_lower = ref.lower()
            if ref_lower.startswith("mailto:"):
                continue
            if "packetstormsecurity.com" in ref_lower:
                continue
            if "securityfocus.com" in ref_lower:
                continue
            if "securitytracker.com" in ref_lower:
                continue
            if not (ref_lower.startswith("http://") or ref_lower.startswith("https://")):
                continue
            filtered.append(ref)
        
        seen = set()
        unique_refs = []
        for r in filtered:
            normalized = r.rstrip('/')
            if normalized not in seen:
                seen.add(normalized)
                unique_refs.append(r)
        
        if unique_refs:
            print("\nOpening up to 5 references in the web browser (no connectivity check):")
            count = 0
            for link in unique_refs:
                if count >= 5:
                    break
                print(link)
                webbrowser.open(link)
                time.sleep(0.5)
                count += 1
        else:
            print("No valid references after filtering.")
    else:
        print("No references found on the page.")
    
    if output_format == "json":
        save_to_json(cve_data, output_filename)
    elif output_format == "csv":
        save_to_csv(cve_data, output_filename)
    elif output_format == "html":
        save_to_html(cve_data, output_filename)
    elif output_format == "pdf":
        save_to_pdf(cve_data, output_filename)
    elif output_format == "md":
        save_to_md(cve_data, output_filename)
    elif output_format == "txt":
        save_to_txt(cve_data, output_filename)
    
    return output_format in ["html", "pdf", "md", "txt"] and os.path.exists(output_filename)

def main():
    print("=== CVE Information Scraper Tool ===\n")
    cve_ids = input("Enter CVE IDs (comma separated): ").split(',')
    out_format = input("Enter output format (json/html/pdf/md/txt): ").strip().lower()
    allowed_formats = ["json", "html", "pdf", "md", "txt"]
    while out_format not in allowed_formats:
        print("Invalid format! Choose one of: json, html, pdf, md, txt.")
        out_format = input("Enter output format (json/html/pdf/md/txt): ").strip().lower()
    out_name = input("Enter output file name (no extension): ").strip()
    
    out_dir = "cve_reports"
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        print(f"Created output directory: {out_dir}")
    
    print("\nStarting CVE processing...")
    reports = []
    for cve_id in cve_ids:
        cve_id = cve_id.strip()
        if not cve_id:
            continue
        full_out = os.path.join(out_dir, f"{out_name}_{cve_id}.{out_format}")
        print(f"\n{'='*50}")
        print(f"Processing: {cve_id}")
        print(f"{'='*50}")
        is_report = process_cve_id(cve_id, out_format, full_out)
        if is_report:
            reports.append(full_out)
    
    if out_format in ["html", "pdf", "md", "txt"] and reports:
        print("\nOpening reports in default browser...")
        for f in reports:
            try:
                webbrowser.open('file://' + os.path.abspath(f))
                time.sleep(0.5)
            except Exception as e:
                print(f"Error opening {f} in browser: {e}")
    
    print(f"\n{'='*50}")
    print(f"Processing complete! Reports are in '{out_dir}'.")
    if out_format in ["html", "pdf", "md", "txt"]:
        print("Open the files in any browser if not opened automatically.")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
