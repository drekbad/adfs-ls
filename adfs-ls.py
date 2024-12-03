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
    Handle both full IP ranges (e.g., "192.168.1.1 - 192.168.1.5") and short octet ranges
    (e.g., "192.168.1.1 - 115"), ensuring outputs are in dotted-decimal format.
    """
    try:
        # Normalize spaces around the hyphen
        range_str = re.sub(r"\s*-\s*", "-", range_str.strip())

        # Check if the range contains a short form (last octet only)
        if "-" in range_str:
            parts = range_str.split("-")
            start_ip_str = parts[0].strip()
            end_part = parts[1].strip()

            # Validate the starting IP
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", start_ip_str):
                raise ValueError(f"Invalid starting IP '{start_ip_str}'.")

            # If end_part is a full IP, treat as a full range
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", end_part):
                start_ip = ip_address(start_ip_str)
                end_ip = ip_address(end_part)
                if start_ip > end_ip:
                    raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}.")
                return [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]

            # Otherwise, assume it's a short octet range
            base_ip, last_octet = start_ip_str.rsplit(".", 1)
            start_octet = int(last_octet)
            end_octet = int(end_part)

            # Validate octet values
            if not (0 <= start_octet <= 255 and 0 <= end_octet <= 255):
                raise ValueError("Octet values must be between 0 and 255.")
            if start_octet > end_octet:
                raise ValueError(f"Start octet {start_octet} is greater than end octet {end_octet}.")

            # Generate the range
            return [f"{base_ip}.{i}" for i in range(start_octet, end_octet + 1)]

        raise ValueError("Invalid range format.")
    except ValueError as e:
        print(f"Invalid IP range '{range_str}': {e}")
        return []

def validate_target(target):
    """
    Validate a single target to ensure it is an IP, range, or FQDN.
    """
    # Match single IP
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        return True
    # Match FQDN
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
        return True
    # Match CIDR or hyphenated range
    if "/" in target or "-" in target:
        return True
    return False

def expand_target_list(targets):
    expanded_targets = set()
    private_ips = set()
    public_ips = set()

    for target in targets:
        target = target.strip()
        if not validate_target(target):
            print(f"Invalid target '{target}' - skipping.")
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  # Single IP
            expanded_targets.add(target)
            (private_ips if ip_address(target).is_private else public_ips).add(target)
        elif "-" in target:  # Hyphenated range
            expanded_targets.update(refined_expand_full_or_short_range(target))
        elif "/" in target:  # CIDR range
            try:
                network = ip_network(target, strict=False)
                expanded_targets.update(str(ip) for ip in network)
            except ValueError as e:
                print(f"Invalid CIDR range '{target}': {e}")
        else:  # Assume domain or FQDN
            expanded_targets.add(target)

    return list(expanded_targets), private_ips, public_ips

def sort_targets(targets):
    """
    Sort targets: FQDNs alphabetically, IPs numerically by octets.
    """
    fqdns = sorted([t for t in targets if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", t)])
    ips = sorted(
        [t for t in targets if re.match(r"^\d+\.\d+\.\d+\.\d+$", t)],
        key=lambda ip: tuple(map(int, ip.split("."))),
    )
    return fqdns + ips

def display_results(results):
    """
    Display the results in a sorted table.
    """
    sorted_targets = sort_targets([result[0] for result in results])
    print(f"{'Target':<40} {'HTTP Code':<10} {'Status':<25}")
    print("=" * 75)
    for target in sorted_targets:
        for result in results:
            if result[0] == target:
                code, status = result[1], result[2]
                color = "green" if status == "Found" else "red"
                print(f"{target:<40} {code:<10} {colored(status, color):<25}")

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

def main():
    args = parse_arguments()
    results = []

    with open(args.input, "r") as file:
        raw_targets = file.read().splitlines()

    expanded_targets, private_ips, public_ips = expand_target_list(raw_targets)

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
    print(f"{'Target':<40} {'HTTP Code':<10} {'Status':<25}")
    print("=" * 75)
    for result in results:
        target, code, status, *_ = result
        color = "green" if status == "Found" else "red"
        print(f"{target:<40} {code:<10} {colored(status, color):<25}")

if __name__ == "__main__":
    main()
