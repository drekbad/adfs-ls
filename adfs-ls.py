def expand_short_hyphen_range(range_str):
    try:
        # Normalize spaces around hyphen and split
        range_str = re.sub(r"\s*-\s*", "-", range_str.strip())
        base, last_part = range_str.rsplit(".", 1)
        if "-" in last_part:
            # Handle cases like "100.100.100.100-115" or "100.100.100.100 - 115"
            start_octet, end_part = last_part.split("-")
            start_octet = int(start_octet)
            if re.match(r"^\d+$", end_part):  # Check if it's a final octet
                end_octet = int(end_part)
                if not (0 <= start_octet <= 255 and 0 <= end_octet <= 255):
                    raise ValueError("Octet values must be between 0 and 255.")
                if start_octet > end_octet:
                    raise ValueError("Start octet is greater than end octet.")
                return {f"{base}.{i}" for i in range(start_octet, end_octet + 1)}
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", end_part):  # Handle full IP
                full_end_ip = ip_address(end_part)
                start_ip = ip_address(f"{base}.{start_octet}")
                if start_ip > full_end_ip:
                    raise ValueError("Start IP is greater than end IP.")
                return {str(ip) for ip in range(int(start_ip), int(full_end_ip) + 1)}
            else:
                raise ValueError("Invalid range format after hyphen.")
        else:
            raise ValueError("Hyphenated range format invalid.")
    except ValueError as e:
        print(f"Invalid IP range '{range_str}': {e}")
        return set()
