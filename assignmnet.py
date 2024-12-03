import re
import csv
from collections import defaultdict, Counter

FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file_path):
    with open(log_file_path, 'r') as file:
        logs = file.readlines()
    return logs

def analyze_logs(logs):
    ip_request_counts = Counter()
    endpoint_access_counts = Counter()
    failed_login_attempts = defaultdict(int)
    
    for log in logs:
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_request_counts[ip_address] += 1
        
        endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE) (/\S*) HTTP', log)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_access_counts[endpoint] += 1
        
        if "401" in log or "Invalid credentials" in log:
            if ip_match:
                failed_login_attempts[ip_address] += 1
    
    suspicious_ips = {
        ip: count for ip, count in failed_login_attempts.items() 
        if count > FAILED_LOGIN_THRESHOLD
    }
    
    return ip_request_counts, endpoint_access_counts, suspicious_ips

def save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_ips, csv_file_path):
    with open(csv_file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_counts.items():
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def display_results(ip_request_counts, most_accessed_endpoint, suspicious_ips):
    print("\nIP Address Requests:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_request_counts.items():
        print(f"{ip:<20}{count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<20}")
    else:
        print("No suspicious activity detected.")

def main():
    log_file_path = 'sample.log'
    csv_file_path = 'log_analysis_results.csv'
    
    logs = parse_log_file(log_file_path)
    ip_request_counts, endpoint_access_counts, suspicious_ips = analyze_logs(logs)
    
    most_accessed_endpoint = endpoint_access_counts.most_common(1)[0]
    
    display_results(ip_request_counts, most_accessed_endpoint, suspicious_ips)
    
    save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_ips, csv_file_path)
    print(f"\nResults saved to {csv_file_path}")

if __name__ == "__main__":
    main()
