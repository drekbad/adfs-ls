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
    Handle both full IP ranges (e.g., "10.10.10.10 - 10.10.10.15") and short octet ranges
    (e.g., "10.10.10.10 - 15").
    """
    try:
        range_str = re.sub(r"\s*-\s*", "-", range_str.strip())  # Normalize spaces around hyphen
        parts = range_str.split("-")

        if len(parts) != 2:
            raise ValueError("Range must contain a start and end value separated by '-'.")

        start_ip_str, end_part = parts[0].strip(), parts[1].strip()

        # Validate starting IP
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", start_ip_str):
            raise ValueError(f"Invalid starting IP '{start_ip_str}': only 3 octets provided.")

        start_ip = ip_address(start_ip_str)

        # Handle full IP end
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", end_part):
            end_ip = ip_address(end_part)
            if start_ip > end_ip:
                raise ValueError(f"Invalid range: starting IP {start_ip} is greater than ending IP {end_ip}.")
            return [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]

        # Handle short octet end (e.g., "10.10.10.10 - 15" or "10.10.10.10 - .15")
        if re.match(r"^\d+$", end_part) or re.match(r"^\.\d+$", end_part):
            base_ip, last_octet = start_ip_str.rsplit(".", 1)
            start_octet = int(last_octet)
            end_octet = int(end_part.strip("."))

            if not (0 <= start_octet <= 255 and 0 <= end_octet <= 255):
                raise ValueError("Invalid octet values: must be between 0 and 255.")
            if start_octet > end_octet:
                raise ValueError(f"Invalid range: starting octet {start_octet} is greater than ending octet {end_octet}.")
            return [f"{base_ip}.{i}" for i in range(start_octet, end_octet + 1)]

        raise ValueError(f"Invalid range format: unexpected end value '{end_part}'.")
    except ValueError as e:
        print(f"Invalid IP range '{range_str}': {e}")
        return []

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
    Expand targets into individual IPs, CIDRs, and FQDNs, with proper sorting.
    """
    expanded_targets = set()

    for target in targets:
        target = target.strip()
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
        elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):  # FQDN
            expanded_targets.add(target)
        else:
            print(f"Invalid target '{target}' - skipping.")

    # Separate IPs and FQDNs for proper sorting
    ips = sorted(
        [t for t in expanded_targets if re.match(r"^\d+\.\d+\.\d+\.\d+$", t)],
        key=lambda ip: tuple(map(int, ip.split("."))),
    )
    fqdns = sorted(
        [t for t in expanded_targets if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", t)]
    )

    return ips + fqdns

def main():
    args = parse_arguments()
    with open(args.input, "r") as file:
        raw_targets = file.read().splitlines()

    expanded_targets = expand_target_list(raw_targets)
    print(f"Expanded Targets: {expanded_targets}")

if __name__ == "__main__":
    main()
