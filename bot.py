import nmap
import os
import json
import re
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import logging
from datetime import datetime
import qrcode  # Import QR code library
import webbrowser  # Import for opening the QR code image
import requests
'''import telegram
from telegram.ext import Updater, CommandHandler'''


# Configure logging
logging.basicConfig(
    filename='/var/log/scan_to_pdf.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info('Script started.')
print("Script started.")

# Start timing for performance measurement
start_time = time.time()

def get_local_ip_and_subnet(interface_name='eth0'):
    logging.info(f"Retrieving local IP and subnet for interface: {interface_name}...")
    print(f"Retrieving local IP and subnet for interface: {interface_name}...")
    if interface_name not in netifaces.interfaces():
        logging.error(f"Interface {interface_name} not found.")
        print(f"Error: Interface {interface_name} not found.")
        return None, None

    addrs = netifaces.ifaddresses(interface_name)
    if netifaces.AF_INET in addrs:
        ip_info = addrs[netifaces.AF_INET][0]
        local_ip = ip_info['addr']
        subnet_mask = ip_info['netmask']
        logging.info(f"Local IP: {local_ip}, Subnet Mask: {subnet_mask}")
        print(f"Local IP: {local_ip}, Subnet Mask: {subnet_mask}")
        return local_ip, subnet_mask
    logging.warning("No IPv4 address found.")
    print("Warning: No IPv4 address found.")
    return None, None

def ping_scan(target):
    logging.info(f"Performing a ping scan on the target: {target}...")
    print(f"Performing a ping scan on the target: {target}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-sn')
        hosts_up = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        logging.info(f"Hosts up: {hosts_up}")
        print(f"Hosts up: {hosts_up}")
        return hosts_up
    except Exception as e:
        logging.error(f"Error during ping scan: {e}")
        print(f"Error during ping scan: {e}")
        return []

def scan_target(target):
    logging.info(f"Scanning target: {target} for open ports and services...")
    print(f"Scanning target: {target} for open ports and services...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-p 1-1000 -sV --script vulners -T4')
        logging.info(f"Scan completed for {target}.")
        print(f"Scan completed for {target}.")
        return target, nm
    except Exception as e:
        logging.error(f"Error scanning {target}: {e}")
        print(f"Error scanning {target}: {e}")
        return target, None

def extract_cve_and_references(json_data):
    logging.info("Extracting CVEs and references...")
    print("Extracting CVEs and references...")
    for target, data in json_data.items():
        for proto in data['protocols']:
            for port in data['protocols'][proto].keys():
                service_info = data['protocols'][proto][port]
                if 'script' in service_info and 'vulners' in service_info['script']:
                    vulns = service_info['script']['vulners']
                    cve_matches = re.findall(r'\bCVE-\d{4}-\d{1,7}\b', vulns)
                    url_matches = re.findall(r'http[s]?://\S+', vulns)

                    service_info['cves'] = list(set(cve_matches))  # All CVEs
                    service_info['references'] = list(set(url_matches))  # All URLs
                    del service_info['script']['vulners']

def extract_and_save_cve_references(json_data, cve_file_path):
    extracted_data = {}
    logging.info(f"Saving CVE references to {cve_file_path}...")
    print(f"Saving CVE references to {cve_file_path}...")

    for target, data in json_data.items():
        services = []
        for proto in data['protocols']:
            for port in data['protocols'][proto].keys():
                service_info = data['protocols'][proto][port]
                
                # Prepare service entry
                entry = {
                    'name': service_info.get('name', 'not found'),
                    'product': service_info.get('product', 'not found'),
                    'version': service_info.get('version', 'not found'),
                    'extrainfo': service_info.get('extrainfo', 'not found'),
                    'cves': [],  # Initialize CVE list
                    'references': []  # Initialize references list
                }
                
                # Extract CVEs and references if present
                if 'cves' in service_info and service_info['cves']:
                    entry['cves'] = service_info['cves']  # All CVEs
                    entry['references'] = [f'https://access.redhat.com/security/cve/{cve}' for cve in entry['cves']]  # References

                services.append(entry)

        # Build the target entry
        extracted_data[target] = {
            'hostname': data.get('hostname', 'not found'),  # Include hostname
            'ip': target,  # Include IP address
            'state': data.get('state', 'not found'),
            'services': services
        }
    
    try:
        with open(cve_file_path, 'w') as cve_file:
            json.dump(extracted_data, cve_file, indent=4)
        logging.info(f"Extracted CVEs and references saved to: {cve_file_path}")
        print(f"Extracted CVEs and references saved to: {cve_file_path}")
    except IOError as e:
        logging.error(f"Failed to write CVE references to {cve_file_path}: {e}")
        print(f"Error: Could not write to file {cve_file_path} due to: {e}")

def save_results_to_json(results, json_file_path):
    logging.info(f"Saving scan results to JSON file: {json_file_path}...")
    print(f"Saving scan results to JSON file: {json_file_path}...")
    json_data = {}

    for target, nm in results.items():
        if target not in nm.all_hosts():
            logging.warning(f"Target {target} not found in scan results.")
            print(f"Warning: Target {target} not found in scan results.")
            continue  # Skip this target if it's not found.

        json_data[target] = {
            'hostname': nm[target].hostname() or target,  # Use the target IP if hostname is not found
            'ip': target,  # Add the IP address
            'state': nm[target].state(),
            'protocols': {}
        }

        for proto in nm[target].all_protocols():
            json_data[target]['protocols'][proto] = {}
            for port in nm[target][proto].keys():
                service_info = nm[target][proto][port]
                json_data[target]['protocols'][proto][port] = service_info

    try:
        with open(json_file_path, 'w') as json_file:
            json.dump(json_data, json_file, indent=4)
        logging.info(f"Results saved to JSON file: {json_file_path}")
        print(f"Results saved to JSON file: {json_file_path}")
        return json_data
    except IOError as e:
        logging.error(f"Failed to write scan results to {json_file_path}: {e}")
        print(f"Error: Could not write to file {json_file_path} due to: {e}")
        return {}

def create_excel_report(cve_file_path, excel_file_path):
    logging.info(f"Creating Excel report at: {excel_file_path}...")
    print(f"Creating Excel report at: {excel_file_path}...")
    try:
        with open(cve_file_path, 'r') as cve_file:
            json_data = json.load(cve_file)

        rows = []
        for service_info in json_data.values():  # Iterate through all targets
            for service in service_info['services']:
                row = {
                    'Hostname': service_info['hostname'],  # Use hostname
                    'IP Address': service_info['ip'],  # Include IP address
                    'State': service_info['state'],
                    'Name': service['name'],
                    'Product': service['product'],
                    'Version': service['version'],
                    'Extra Info': service['extrainfo'],
                    'CVE': ', '.join(service['cves']),  # Join multiple CVEs
                    'Reference': ', '.join(service['references'])  # Join multiple references
                }
                rows.append(row)

        df = pd.DataFrame(rows)
        df.to_excel(excel_file_path, index=False)
        logging.info(f"Excel report created successfully at: {excel_file_path}")
        print(f"Excel report created successfully at: {excel_file_path}")
    except IOError as e:
        logging.error(f"Failed to create Excel report at {excel_file_path}: {e}")
        print(f"Error: Could not create Excel report due to: {e}")

def create_qr_code(link, file_path):
    logging.info(f"Creating QR code for: {link}...")
    print(f"Creating QR code for: {link}...")
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(link)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    img.save(file_path)
    logging.info(f"QR code saved to: {file_path}")
    print(f"QR code saved to: {file_path}")

def create_html_report(cve_file_path, html_file_path, qr_code_path):
    logging.info(f"Creating HTML report at: {html_file_path}...")
    print(f"Creating HTML report at: {html_file_path}...")
    
    try:
        with open(cve_file_path, 'r') as cve_file:
            json_data = json.load(cve_file)

        # Start building the HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Scan Results</title>
            <style>
                body {{
                    font-family: 'Arial', sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f4f4f4;
                    color: #333;
                }}
                h1 {{
                    text-align: center;
                    color: #007BFF;
                    margin-bottom: 20px;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background: #fff;
                    border-radius: 8px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }}
                .service {{
                    margin-bottom: 40px;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    background: #f9f9f9;
                }}
                h2 {{
                    color: #333;
                    border-bottom: 2px solid #007BFF;
                    padding-bottom: 10px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border: 1px solid #ddd;
                }}
                th {{
                    background-color: #007BFF;
                    color: #fff;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                tr:hover {{
                    background-color: #eaeaea;
                }}
                /* Responsive styles */
                @media (max-width: 768px) {{
                    h1 {{
                        font-size: 24px;
                    }}
                    table {{
                        font-size: 14px;
                    }}
                    .service {{
                        padding: 15px;
                    }}
                }}
                @media (max-width: 480px) {{
                    h1 {{
                        font-size: 20px;
                    }}
                    th, td {{
                        padding: 10px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Scan Results</h1>
                <p><a href="/index.html" target="_blank">Back </a></p> 
        """

        for target, data in json_data.items():
            # Add target information
            html_content += f"<div class='service'><h2>Target: {data['hostname']} ({target})</h2>"
            html_content += f"<p>Status: <strong>{data['state']}</strong></p>"
            html_content += "<table><tr><th>Name</th><th>Product</th><th>Version</th><th>Extra Info</th><th>CVE</th><th>References</th></tr>"

            for service in data['services']:
                cve_list = ', '.join(service['cves']) if service['cves'] else 'None'
                reference_list = ', '.join(service['references']) if service['references'] else 'None'
                html_content += f"<tr><td>{service['name']}</td><td>{service['product']}</td><td>{service['version']}</td><td>{service['extrainfo']}</td><td>{cve_list}</td><td><a href={reference_list}>{reference_list}</a></td></tr>"

            html_content += "</table></div>"

        html_content += """
            </div>
        </body>
        </html>
        """

        with open(html_file_path, 'w') as html_file:
            html_file.write(html_content)

        logging.info(f"HTML report created successfully at: {html_file_path}")
        print(f"HTML report created successfully at: {html_file_path}")
    
    except IOError as e:
        logging.error(f"Failed to create HTML report at {html_file_path}: {e}")
        print(f"Error: Could not create HTML report due to: {e}")
import requests
import qrcode
import netifaces as ni
from PIL import Image

# Function to get Raspberry Pi's IP address and send it along with QR code to Telegram
'''def send_ip_and_qr_to_telegram(bot_token, chat_id):
    # Get the Raspberry Pi's IP address
    interface = 'eth0'  # Use 'eth0' for wired connection or 'wlan0' for wireless
    try:
        ip_address = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    except KeyError:
        ip_address = 'IP not found'

    # Generate a QR code with the IP address
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(f"http://{local_ip}/scan_{timestamp}/result.html")
    qr.make(fit=True)

    # Create an image from the QR Code
    img = qr.make_image(fill='black', back_color='white')
    qr_code_path = 'qr_code.png'
    img.save(qr_code_path)

    # Send IP address as a message to Telegram
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    response = requests.post(url, data={'chat_id': chat_id, 'text': f"IP Address: {ip_address}"})
    print(response.json())

    # Send the QR code image to Telegram
    url_send_photo = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    with open(qr_code_path, 'rb') as photo:
        response = requests.post(url_send_photo, data={'chat_id': chat_id}, files={'photo': photo})
    print(response.json())

# Your bot token and chat ID
bot_token = '7220476758:AAF-ub9SlYlCVYqUNGHkR0Ex8lK3bpzRImw'
chat_id = '911566955'''

# Call the single function to send the IP and QR code


if __name__ == '__main__':
    logging.info("Starting the scanning process...")
    print("Starting the scanning process...")

    # Get local IP and subnet
    local_ip, subnet_mask = get_local_ip_and_subnet()
    if local_ip and subnet_mask:
        target = local_ip + "/24"
    else:
        logging.warning("Could not retrieve local IP or subnet mask, defaulting to scanme.nmap.org.")
        print("Warning: Could not retrieve local IP or subnet mask, defaulting to scanme.nmap.org.")
        target = "scanme.nmap.org"

    logging.info("Please wait while the scan is in progress...")
    print("Please wait while the scan is in progress...")
    hosts_up = ping_scan(target)

    results = {}
    if hosts_up:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_target, host): host for host in hosts_up}
            for future in as_completed(futures):
                target, nm = future.result()
                if nm:
                    results[target] = nm
                    logging.info(f"Results received for {target}.")
                    print(f"Results received for {target}.")
                else:
                    logging.warning(f"No results for {target}, continuing to next target.")

    logging.info("Scanning complete. Saving results...\n")
    print("Scanning complete. Saving results...\n")

    # Create a directory with the current date and time
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = f"/var/www/html/scan/scan_{timestamp}"
    try:
        os.makedirs(report_dir, exist_ok=True)
        logging.info(f"Report directory created: {report_dir}")
        print(f"Report directory created: {report_dir}")
    except OSError as e:
        logging.error(f"Failed to create directory {report_dir}: {e}")
        print(f"Error: Could not create directory {report_dir} due to: {e}")
        exit(1)  # Exit if the directory creation fails

    # Save JSON file outside the report directory
    json_file_path = "nmap_scan_results.json"  # Save JSON file in the current directory
    excel_file_path = os.path.join(report_dir, "nmap_scan_report.xlsx")
    cve_file_path = os.path.join(report_dir, "extracted_cves.json")
    html_file_path = os.path.join(report_dir, "result.html")  # Define the path for result.html

    if results:
        json_data = save_results_to_json(results, json_file_path)
        extract_cve_and_references(json_data)
        extract_and_save_cve_references(json_data, cve_file_path)
        create_excel_report(cve_file_path, excel_file_path)

        # Create the QR code for the result.html file
        qr_code_link = f"http://{local_ip}/scan_{timestamp}/result.html"
        qr_code_path = os.path.join(report_dir, "scan_qr_code.png")  # Define path for QR code image
        create_qr_code(qr_code_link, qr_code_path)

        
        # Open the QR code image
        #webbrowser.open(qr_code_path)  # Open the QR code in the default web browser

        # Create the HTML report with the QR code path
        create_html_report(cve_file_path, html_file_path, qr_code_path)
        #send_ip_and_qr_to_telegram(bot_token, chat_id)
    else:
        logging.warning("No scan results to report.")
        print("Warning: No scan results to report.")

    # Try opening the JSON file if it exists
    """if os.path.exists(cve_file_path):
        os.system(f"xdg-open {cve_file_path}")
    else:
        logging.error(f"CVE file not found: {cve_file_path}")
        print(f"Error: CVE file not found: {cve_file_path}")"""

    # Open the HTML report if it exists
    """if os.path.exists(html_file_path):
        os.system(f"xdg-open {html_file_path}")
    else:
        logging.error(f"HTML report not found: {html_file_path}")
        print(f"Error: HTML report not found: {html_file_path}")"""

    end_time = time.time()
    duration = end_time - start_time
    logging.info(f"Total time taken: {duration:.2f} seconds")
    print(f"Total time taken: {duration:.2f} seconds")

import requests
import openai
import time
import json

# Set your OpenAI API key
openai.api_key = ''

# Fetch CVE details from CIRCL API
def get_cve_info(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json() if response.json() else None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {cve_id}: {e}")
        return None

# Generate mitigation steps using GPT-4
def generate_solution(prompt):
    retry_attempts = 5
    for attempt in range(retry_attempts):
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.7
            )
            return response['choices'][0]['message']['content']
        except openai.error.RateLimitError:
            print("Rate limit exceeded. Retrying in 60 seconds...")
            time.sleep(60)
        except openai.error.OpenAIError as e:
            print(f"OpenAI API Error: {e}")
            return None
    return None

# Read CVEs from the JSON data
def extract_cves_from_json(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            
        cve_list = []
        # Iterate over each host
        for host, details in data.items():
            services = details.get("services", [])
            for service in services:
                cves = service.get("cves", [])
                for cve in cves:
                    cve_list.append({"cve_id": cve, "host": host, "service": service['name']})
                    
        return cve_list
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error decoding JSON in {file_path}.")
        return []

# Save mitigation results to a JSON file
def save_to_json(data, filename='mitigation.json'):
    report_dir = f"/var/www/html/scan/scan_{timestamp}"
    
    # Create the report directory if it doesn't exist
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    file_path = os.path.join(report_dir, filename)
    
    try:
        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"Mitigation data saved to {file_path}")
    except Exception as e:
        print(f"Error saving to {file_path}: {e}")
# Process the CVEs and generate solutions
def process_cves(file_path):
    cve_entries = extract_cves_from_json(file_path)
    
    if not cve_entries:
        print("No CVEs found in the JSON data.")
        return

    mitigation_results = {}

    for entry in cve_entries:
        cve_id = entry['cve_id']
        host = entry['host']
        service_name = entry['service']
        
        print(f"\nProcessing {cve_id} for host {host} (service: {service_name})...")
        
        # Fetch CVE details
        cve_info = get_cve_info(cve_id)
        if not cve_info:
            print(f"Could not retrieve information for {cve_id}")
            continue
        
        cve_summary = cve_info.get('summary', 'No summary available')
        
        # Generate solution prompt
        prompt = (
            f"Based on the CVE summary: '{cve_summary}', provide clear, actionable steps to mitigate this vulnerability. "
            "Make the solution understandable to both technical experts and non-experts. Use a numbered list for clarity."
        )
        solution = generate_solution(prompt)
        
        # Store the results in a dictionary
        mitigation_results[cve_id] = {
            "host": host,
            "service": service_name,
            "summary": cve_summary,
            "solution": solution if solution else "No solution available"
        }

    # Save the results to a JSON file
    save_to_json(mitigation_results)

if __name__ == "__main__":
    # Specify the path to your JSON file
    json_file_path = os.path.join(report_dir, "extracted_cves.json")
    process_cves(json_file_path)


