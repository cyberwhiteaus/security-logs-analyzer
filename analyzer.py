# SECURITY LOG ANALYZER
# A simple tool to detect cyber attacks in server logs

print(">>> Starting Security Log Analyzer...")
print("=" * 50)


# STEP 1: Function to read the log file
def read_log_file(file_path):
    print(f">>> Reading log file: {file_path}")
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        print(f">>> Found {len(logs)} log entries")
        return logs
    except FileNotFoundError:
        print(">>> Error: Log file not found!")
        return []


# STEP 2: Function to understand each log line
def parse_log_line(line):
    parts = line.split()
    if len(parts) < 7:
        return None

    ip_address = parts[0]
    request_url = parts[6]

    return {
        'ip': ip_address,
        'url': request_url,
        'full_line': line.strip()
    }


# STEP 3: Detect brute-force attacks
def detect_brute_force(parsed_logs):
    print("\n>>> Checking for Brute-force attacks...")

    ip_counter = {}

    for log in parsed_logs:
        if log:
            ip = log['ip']
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    # Find suspicious IPs (more than 3 requests)
    suspicious_ips = {}
    for ip, count in ip_counter.items():
        if count > 3:
            suspicious_ips[ip] = count

    return suspicious_ips


# STEP 4: Detect SQL injection attacks
def detect_sql_injection(parsed_logs):
    print(">>> Checking for SQL Injection attacks...")

    # Common SQL injection keywords to look for
    sql_keywords = ["'", "1=1", "OR", "UNION", "SELECT", "DROP", "INSERT"]

    suspicious_requests = []

    for log in parsed_logs:
        if log:
            url_upper = log['url'].upper()  # Convert to uppercase for case-insensitive check

            # Check if any SQL keyword appears in the URL
            for keyword in sql_keywords:
                if keyword.upper() in url_upper:
                    print(f">>> Found '{keyword}' in request from {log['ip']}")
                    suspicious_requests.append(log)
                    break  # Found one keyword, no need to check others

    return suspicious_requests


# STEP 5: Generate final security report
def generate_report(brute_force_ips, sql_injections):
    print("\n" + "=" * 50)
    print(">>> FINAL SECURITY REPORT")
    print("=" * 50)

    # Brute-force section
    if brute_force_ips:
        print("\n>>> BRUTE-FORCE ATTACKS DETECTED:")
        for ip, count in brute_force_ips.items():
            print(f"   IP: {ip}")
            print(f"   - {count} login attempts (suspicious!)")
    else:
        print("\n>>> No brute-force attacks detected")

    # SQL Injection section
    if sql_injections:
        print("\n>>> SQL INJECTION ATTACKS DETECTED:")
        for attack in sql_injections:
            print(f"   IP: {attack['ip']}")
            print(f"   - Suspicious URL: {attack['url']}")
    else:
        print("\n>>> No SQL injection attacks detected")

    # Summary
    total_threats = len(brute_force_ips) + len(sql_injections)
    print(f"\n>>> SUMMARY: Found {total_threats} types of security threats")


# MAIN PROGRAM
def main():
    print(">>> Program started!")

    # Read the log file
    logs = read_log_file("sample_logs.txt")

    if not logs:
        print(">>> No logs to analyze. Exiting.")
        return

    # Parse each log line
    print("\n>>> Parsing log entries...")
    parsed_logs = []

    for line in logs:
        parsed_line = parse_log_line(line)
        if parsed_line:
            parsed_logs.append(parsed_line)

    print(f">>> Successfully parsed {len(parsed_logs)} log entries")

    # Run security detection
    brute_force_ips = detect_brute_force(parsed_logs)
    sql_injections = detect_sql_injection(parsed_logs)

    # Generate final report
    generate_report(brute_force_ips, sql_injections)

    print("\n>>> Analysis complete!")
    print(">>> Check the report above for security threats")


# This line makes sure our program runs when we execute the file
if __name__ == "__main__":
    main()
