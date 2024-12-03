import argparse
import requests
from bs4 import BeautifulSoup
from termcolor import colored
from ipaddress import ip_address, ip_network
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

def refined_expand_full_or_short_range(range_str):
    """
    Handle full IP ranges (e.g., "192.168.1.1 - 192.168.1.5") and short octet ranges
    (e.g., "192.168.1.1 - 115").
    """
    try:
        range_str = re.sub(r"\s*-\s*", "-", range_str.strip())  # Normalize spaces around hyphen
        parts = range_str.split("-")
        
        if len(parts) != 2:
            raise ValueError("Range must contain a start and end value separated by '-'.")

        start_ip_str, end_part = parts[0].strip(), parts[1].strip()

        # Validate starting IP
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", start_ip_str):
            raise ValueError(f"Invalid starting IP '{start_ip_str}'.")
        start_ip = ip_address(start_ip_str)

        # Handle full IP end
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", end_part):
            end_ip = ip_address(end_part)
            if start_ip > end_ip:
                raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}.")
            return [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]

        # Handle short octet end
        if re.match(r"^\d+$", end_part):
            base_ip, last_octet = start_ip_str.rsplit(".", 1)
            start_octet = int(last_octet)
            end_octet = int(end_part)
            if not (0 <= start_octet <= 255 and 0 <= end_octet <= 255):
                raise ValueError("Octet values must be between 0 and 255.")
            if start_octet > end_octet:
                raise ValueError(f"Start octet {start_octet} is greater than end octet {end_octet}.")
            return [f"{base_ip}.{i}" for i in range(start_octet, end_octet + 1)]

        raise ValueError(f"Invalid end value '{end_part}'.")
    except ValueError as e:
        return [f"Invalid IP range '{range_str}': {e}"]

def validate_target(target):
    """
    Validate single target as IP, range, or FQDN.
    """
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  # Single IP
        return True
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):  # FQDN
        return True
    if re.match(r"^\d+\.\d+\.\d+\.\d+[-/]", target):  # IP range or CIDR
        return True
    return False

def expand_target_list(targets):
    """
    Expand targets into individual IPs, CIDRs, and FQDNs.
    """
    expanded_targets = set()
    for target in targets:
        target = target.strip()
        if not validate_target(target):
            print(f"Invalid target '{target}' - skipping.")
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  # Single IP
            expanded_targets.add(target)
        elif "-" in target:  # Range
            expanded_targets.update(refined_expand_full_or_short_range(target))
        elif "/" in target:  # CIDR
            try:
                network = ip_network(target, strict=False)
                expanded_targets.update(str(ip) for ip in network)
            except ValueError as e:
                print(f"Invalid CIDR range '{target}': {e}")
        else:  # FQDN
            expanded_targets.add(target)
    return sorted(expanded_targets, key=lambda x: tuple(map(int, x.split("."))) if re.match(r"^\d+\.\d+\.\d+\.\d+$", x) else x)

def main():
    args = parse_arguments()
    with open(args.input, "r") as file:
        raw_targets = file.read().splitlines()

    expanded_targets = expand_target_list(raw_targets)
    print(f"Expanded Targets: {expanded_targets}")

if __name__ == "__main__":
    main()
