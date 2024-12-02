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

def construct_url(target, path="/adfs/ls/idpinitiatedsignon.aspx"):
    if ":" in target:
        host, port = target.rsplit(":", 1)
        if port == "80":
            return f"http://{host}{path}"
        return f"https://{host}:{port}{path}"
    return f"https://{target}{path}"

def check_adfs_target(target, timeout):
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
            return response.status_code, "Found", options
        return response.status_code, "Not Found", []
    except requests.exceptions.RequestException as e:
        return "Error", str(e), []

def fetch_metadata(target, timeout):
    url = construct_url(target, path="/FederationMetadata/2007-06/FederationMetadata.xml")
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return url, response.text
        return url, None
    except requests.exceptions.RequestException:
        return url, None

def parse_metadata(xml_content):
    try:
        root = ET.fromstring(xml_content)
        namespaces = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
        endpoints = set()  # Use a set to deduplicate entries
        for endpoint in root.findall(".//md:AssertionConsumerService", namespaces):
            location = endpoint.get("Location")
            if location:
                endpoints.add(location)
        return list(endpoints)
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
            metadata_url, metadata_content = fetch_metadata(target.strip(), args.timeout)
            if metadata_content:
                metadata_found[target] = (metadata_url, parse_metadata(metadata_content))
            else:
                metadata_found[target] = (metadata_url, None)

    # Display results for sign-on page checks
    display_results(results)

    # Display relying party dropdown contents
    if options_found:
        print("\nEnumerated Relying Parties:")
        for target, options in options_found.items():
            print(f"\nTarget: {target}")
            for human_readable, alphanumeric_id in options:
                print(f"  - {human_readable} ({alphanumeric_id})")

    # Display metadata results
    if metadata_found:
        print("\nMetadata Results:")
        for target, (metadata_url, endpoints) in metadata_found.items():
            print(f"\nTarget: {target}")
            print(f"  Metadata URL: {metadata_url}")
            if endpoints:
                print("  Contents:")
                for endpoint in endpoints:
                    print(f"    - {endpoint}")
            else:
                print("  No metadata contents found.")

if __name__ == "__main__":
    main()
