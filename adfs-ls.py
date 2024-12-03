import argparse
import requests
from bs4 import BeautifulSoup
from termcolor import colored
from xml.etree import ElementTree as ET
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Lock for thread-safe output
output_lock = Lock()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Check ADFS URL for dropdown field and extract options.")
    parser.add_argument("-i", "--input", required=True, help="Input file containing FQDNs or IPs.")
    parser.add_argument("-o", "--output", help="Output file to save the results.")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5).")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10, max: 50).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for detailed error information.")
    return parser.parse_args()

def construct_url(target, path="/adfs/ls/idpinitiatedsignon.aspx"):
    if ":" in target:
        host, port = target.rsplit(":", 1)
        if port == "80":
            return f"http://{host}{path}"
        return f"https://{host}:{port}{path}"
    return f"https://{target}{path}"

def check_adfs_target(target, timeout, verbose):
    url = construct_url(target)
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200 and "idp_RelyingPartyDropDownList" in response.text:
            soup = BeautifulSoup(response.text, "html.parser")
            dropdown = soup.find("select", id="idp_RelyingPartyDropDownList")
            options = []
            if dropdown:
                for option in dropdown.find_all("option"):
                    human_readable = option.text.strip()
                    alphanumeric_id = option.get("value", "N/A")
                    options.append((human_readable, alphanumeric_id))
            return target, response.status_code, "Found", options
        return target, response.status_code, "Not Found", []
    except requests.exceptions.RequestException as e:
        error_message = str(e)
        if "Max retries exceeded" in error_message:
            concise_error = "No response on port 443"
        else:
            concise_error = "Request error"
        return target, "Error", error_message if verbose else concise_error, []

def process_target(target, timeout, verbose):
    code, status, options = check_adfs_target(target, timeout, verbose)[1:]
    metadata_url, metadata_content = fetch_metadata(target.strip(), timeout)
    endpoints, related_urls, external_urls = [], [], []
    if metadata_content:
        endpoints, related_urls, external_urls = parse_metadata(metadata_content, target.strip())
    return target, code, status, options, metadata_url, endpoints, related_urls, external_urls

def fetch_metadata(target, timeout):
    url = construct_url(target, path="/FederationMetadata/2007-06/FederationMetadata.xml")
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return url, response.text
        return url, None
    except requests.exceptions.RequestException:
        return url, None

def parse_metadata(xml_content, target):
    try:
        root = ET.fromstring(xml_content)
        namespaces = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
        endpoints = set()
        for endpoint in root.findall(".//md:AssertionConsumerService", namespaces):
            location = endpoint.get("Location")
            if location:
                endpoints.add(location)

        all_urls = set(re.findall(r"https?://[^\s\"<>]+", xml_content))
        related_urls = sorted({
            url for url in all_urls
            if target in url and not any(excluded in url for excluded in ["schemas.xmlsoap.org", "docs.oasis-open.org", "www.w3.org"])
        })
        external_urls = sorted({
            url for url in all_urls
            if target not in url and not any(excluded in url for excluded in ["microsoft.com", "schemas.xmlsoap.org", "docs.oasis-open.org", "www.w3.org"])
        })
        return list(endpoints), related_urls, external_urls
    except ET.ParseError:
        return [], [], []

def display_progress(total, completed):
    with output_lock:
        print(f"\rSearching for ADFS targets... {completed}/{total} completed", end="", flush=True)

def main():
    args = parse_arguments()
    results = []
    output_content = []

    with open(args.input, "r") as file:
        targets = file.read().splitlines()

    print("Starting search with threading...")
    total_targets = len(targets)
    completed_targets = 0

    with ThreadPoolExecutor(max_workers=min(args.threads, 50)) as executor:
        futures = {executor.submit(process_target, target, args.timeout, args.verbose): target for target in targets}

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed_targets += 1
            display_progress(total_targets, completed_targets)

    print("\nProcessing complete.\n")

    # Display results
    found_adfs = False
    print(f"{'Target':<40} {'HTTP Code':<10} {'Status':<25}")
    print("=" * 75)
    for target, code, status, _, _, _, _, _ in results:
        color = "green" if status == "Found" else "red"
        print(f"{target:<40} {code:<10} {colored(status, color):<25}")
        if status == "Found":
            found_adfs = True

    # Add summary if no ADFS/IDP services were identified
    if not found_adfs:
        print("\nNo ADFS/IDP services identified for the provided targets.")

    # Further processing and output logic...

    if args.output:
        write_to_file(args.output, "".join(output_content))

if __name__ == "__main__":
    main()
