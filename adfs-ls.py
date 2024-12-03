#!/usr/bin/env python3

import argparse
import requests
from bs4 import BeautifulSoup
from termcolor import colored
from ipaddress import ip_network, ip_address
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Lock for thread-safe output
output_lock = Lock()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Check ADFS URL for dropdown field and extract options.")
    parser.add_argument("-i", "--input", required=True, help="Input file containing FQDNs, IPs, or ranges.")
    parser.add_argument("-o", "--output", help="Output file to save the results.")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5).")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10, max: 50).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for detailed error information.")
    return parser.parse_args()

def expand_target_list(targets):
    expanded_targets = set()
    private_ips = set()
    public_ips = set()

    for target in targets:
        target = target.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  # Single IP
            expanded_targets.add(target)
            (private_ips if is_private_ip(target) else public_ips).add(target)
        elif re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", target):  # Hyphenated range, short form
            expanded_targets.update(expand_short_hyphen_range(target))
        elif "-" in target:  # Full dotted octet range (e.g., 192.168.1.1-192.168.1.5)
            expanded_targets.update(expand_full_hyphen_range(target))
        elif "/" in target:  # CIDR range
            expanded_targets.update(expand_cidr_range(target))
        else:  # Domain or FQDN
            expanded_targets.add(target)

    return list(expanded_targets), private_ips, public_ips

def expand_cidr_range(cidr):
    try:
        network = ip_network(cidr, strict=False)
        return {str(ip) for ip in network}
    except ValueError as e:
        print(f"Invalid CIDR range '{cidr}': {e}")
        return set()

def expand_short_hyphen_range(range_str):
    try:
        base, last_part = range_str.rsplit(".", 1)
        if "-" in last_part:  # Handle cases like "100.100.100.100 - 115"
            start_octet, end_octet = map(int, last_part.split("-"))
            if not (0 <= start_octet <= 255 and 0 <= end_octet <= 255):
                raise ValueError("Octet values must be between 0 and 255.")
            if start_octet > end_octet:
                raise ValueError("Start octet is greater than end octet.")
            return {f"{base}.{i}" for i in range(start_octet, end_octet + 1)}
        else:
            raise ValueError("Hyphenated range format invalid.")
    except ValueError as e:
        print(f"Invalid IP range '{range_str}': {e}")
        return set()

def expand_full_hyphen_range(range_str):
    try:
        start, end = range_str.split("-")
        start_ip = ip_address(start.strip())
        end_ip = ip_address(end.strip())
        if start_ip > end_ip:
            raise ValueError("Start IP is greater than end IP in range.")
        return {str(ip) for ip in range(int(start_ip), int(end_ip) + 1)}
    except ValueError as e:
        print(f"Invalid IP range '{range_str}': {e}")
        return set()

def is_private_ip(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False

def warn_and_confirm(private_ips, public_ips):
    if private_ips and public_ips:
        print(colored("Warning: Both private and public IPs detected.", "yellow"))
        print(f"Private IPs: {', '.join(private_ips)}")
        print(f"Public IPs: {', '.join(public_ips)}")
        confirm = input("Do you want to proceed? (y/N): ").strip().lower()
        if confirm != "y":
            print("Aborting...")
            exit()

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
    return check_adfs_target(target, timeout, verbose)

def display_progress(total, completed):
    with output_lock:
        print(f"\rSearching for ADFS targets... {completed}/{total} completed", end="", flush=True)

def write_to_file(file_path, content):
    with open(file_path, "w") as file:
        file.write(content)

def main():
    args = parse_arguments()
    results = []
    output_content = []

    with open(args.input, "r") as file:
        raw_targets = file.read().splitlines()

    expanded_targets, private_ips, public_ips = expand_target_list(raw_targets)
    warn_and_confirm(private_ips, public_ips)

    print("Starting search with threading...")
    total_targets = len(expanded_targets)
    completed_targets = 0

    with ThreadPoolExecutor(max_workers=min(args.threads, 50)) as executor:
        futures = {executor.submit(process_target, target, args.timeout, args.verbose): target for target in expanded_targets}

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
    for result in results:
        target, code, status, *_ = result
        color = "green" if status == "Found" else "red"
        print(f"{target:<40} {code:<10} {colored(status, color):<25}")
        if status == "Found":
            found_adfs = True

    if not found_adfs:
        print("\nNo ADFS/IDP services identified for the provided targets.")

    if args.output:
        write_to_file(args.output, "".join(output_content))

if __name__ == "__main__":
    main()
