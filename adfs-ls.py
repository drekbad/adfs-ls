import argparse
import requests
from bs4 import BeautifulSoup
from termcolor import colored
from xml.etree import ElementTree as ET

def parse_arguments():
    parser = argparse.ArgumentParser(description="Check ADFS URL for dropdown field and extract options.")
    parser.add_argument("-i", "--input", required=True, help="Input file containing FQDNs or IPs.")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5).")
    return parser.parse_args()

def check_adfs_target(target, timeout):
    url = f"http://{target}/adfs/ls/idpinitiatedsignon.aspx"
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
            return response.status_code, "Found", options
        return response.status_code, "Not Found", []
    except requests.exceptions.RequestException as e:
        return "Error", str(e), []

def fetch_metadata(target, timeout):
    metadata_url = f"https://{target}/FederationMetadata/2007-06/FederationMetadata.xml"
    try:
        response = requests.get(metadata_url, timeout=timeout)
        if response.status_code == 200:
            return response.text
        return None
    except requests.exceptions.RequestException as e:
        return None

def parse_metadata(xml_content):
    try:
        root = ET.fromstring(xml_content)
        namespaces = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
        endpoints = []
        for endpoint in root.findall(".//md:AssertionConsumerService", namespaces):
            location = endpoint.get("Location")
            if location:
                endpoints.append(location)
        return endpoints
    except ET.ParseError:
        return []

def display_results(results):
    print(f"{'Target':<40} {'HTTP Code':<10} {'Status':<10}")
    print("=" * 60)
    for result in results:
        target, code, status = result[:3]
        color = "green" if status == "Found" else "red"
        print(f"{target:<40} {code:<10} {colored(status, color):<10}")

def main():
    args = parse_arguments()
    results = []
    options_found = {}
    metadata_found = {}

    with open(args.input, "r") as file:
        targets = file.read().splitlines()

    for target in targets:
        code, status, options = check_adfs_target(target.strip(), args.timeout)
        results.append((target, code, status))
        if status == "Found" and options:
            options_found[target] = options
            metadata = fetch_metadata(target.strip(), args.timeout)
            if metadata:
                metadata_found[target] = parse_metadata(metadata)

    display_results(results)

    if options_found:
        print("\nDropdown contents found:")
        for target, options in options_found.items():
            print(f"\nTarget: {target}")
            for human_readable, alphanumeric_id in options:
                print(f"{human_readable} ({alphanumeric_id})")

    if metadata_found:
        print("\nMetadata contents found:")
        for target, endpoints in metadata_found.items():
            print(f"\nTarget: {target}")
            for endpoint in endpoints:
                print(endpoint)

if __name__ == "__main__":
    main()