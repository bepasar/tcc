from collections import Counter, defaultdict
from typing import Optional, Tuple
import os, sys, re, gzip
import urllib.parse
import ipaddress
import pandas as pd 

""" 
    This script processes payloads from a CSV file, extracting URLs, server domains/IPs, and filenames
    from commands wget, curl, tftp, and ftpget. It decodes hex-encoded payloads, identifies command
    patterns, checks for invalid urls and then produces a quantitative summary for URLs, filenames, 
    and commands based on the destination port (23 or non-23). 
    The results are saved to text files for further analysis.
    Usage: zcat *.csv.gz | python3 4_payload_analysis.py
"""

#------------------------------ Defining regex patterns ------------------------------#

# matches specific commands and their arguments
command_pattern = re.compile(
    r"""
    (?P<command>wget|curl|tftp|ftpget)
    (?!\.)
    (?P<args>[^\n;&|]*) # OK manual tests
    # (?P<args>[^\n;&|<`)]*) # added <`)
    """, re.VERBOSE
)

# matches string after '-r' flag 
remote_filename_pattern = re.compile(
    r"""
    -r\s+([^\s;|]+)
    """, re.VERBOSE
)

url_like_pattern = re.compile(
    r"""
    (
        (?P<scheme>https?://)?                  # Optional http:// or https://
        (?P<host>                               # Domain or IP
            [a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}       # Domain (e.g., example.com)
            |                                   # or
            (?P<ipv4>(?:\d{1,3}\.){3}\d{1,3})   # IPv4
        )
        (?P<port>:\d+)?                         # Optional port
        (?P<path>/[^\s'";|\\]+)                 # Slash and path (at least one char)
    )
    """, re.VERBOSE
)

ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
busybox_pattern = re.compile(r"/bin/busybox\s+(\S+)\s*$")

#------------------------------ Defining regex patterns ------------------------------#

#------------------------------ Defining counters and mappings ------------------------------#
# stats for logging
total_payload = 0 # total payloads processed
malicious_payload = 0  # malicious payloads (contains valid download commands and valid urls)

# overall counters and mappings
# Centralized stats for servers, urls, filenames, src_ips, ports
server_stats = defaultdict(lambda: {
    "ips": set(),
    "filenames": set(),
    "urls": set(),
    "ports": set(),
    "count": 0
})
url_stats = defaultdict(lambda: {
    "src_ips": set(),
    "servers": set(),
    "filenames": set(),
    "ports": set(),
    "count": 0
})
filename_stats = defaultdict(lambda: {
    "src_ips": set(),
    "servers": set(),
    "urls": set(),
    "ports": set(),
    "count": 0
})
# Tracks statistics for each source IP, including:
# - urls: Set of URLs accessed by the source IP
# - servers: Set of servers contacted by the source IP
# - filenames: Set of filenames downloaded by the source IP
# - ports: Set of destination ports used by the source IP
# - count: Total number of payloads associated with the source IP
src_ip_stats = defaultdict(lambda: {
    "urls": set(),
    "servers": set(),
    "filenames": set(),
    "ports": set(),
    "count": 0
})
port_stats = defaultdict(lambda: {
    "src_ips": set(),
    "urls": set(),
    "servers": set(),
    "filenames": set(),
    "count": 0
})
command_stats = defaultdict(int)

#------------------------------ Defining counters and mappings ------------------------------#

#------------------------------ Defining functions for processing ------------------------------#
def decode_payload(hex_payload) -> str:
    """Decode from hex, URL-encoded and obfuscated payloads."""
    # hex to text
    payload = bytes.fromhex(hex_payload).decode("utf-8", errors="ignore")

    # URL-decoding
    if '%' in payload or '+' in payload:
        decoded = urllib.parse.unquote_plus(payload)
    else:
        decoded = payload

    # de-obfuscate common patterns
    if r'${IFS}' in decoded:
        decoded = decoded.replace(r'${IFS}', ' ')

    return decoded

def extract_command_chunks(decoded_payload, command_chunk_pattern):
    """Yield (command, args) tuples from command patterns found in a payload."""
    for chunk in command_chunk_pattern.finditer(decoded_payload):
        command = chunk.group('command')
        args = chunk.group('args').strip()
        yield command, args

def is_invalid_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_multicast or
            ip_obj.is_reserved
        )
    except ValueError:
        return True  # Not a valid IP address
    
def is_invalid_url(url) -> bool:

    if any(c in url for c in '%<>\\^`{|}'): # forbidden characters (RFC 3986)
        return True
    return False

def process_url_match(args) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Process URLs, and extract server domains/IPs, and filenames."""
    url_match = url_like_pattern.search(args)
    if url_match:
        url = url_match.group()
        if is_invalid_url(url):
            return None, None, None
    else:
        return None, None, None

    server = url_match.group('ipv4')
    if server:  # If an IPv4 match is found, use it
        if is_invalid_ip(server):
            return None, None, None
    else:  # If no IPv4 match, try to get the host domain
        server = url_match.group('host')
        if not server:  # If no host or IP found, return None
            return None, None, None

    filename = url_match.group('path').split('/')[-1]  # Extract the path and get filename

    return url, server, filename

def process_curl(args) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Process curl command arguments to extract URLs and filenames."""
    # Extract URL-like patterns in curl arguments
    url, server, filename = process_url_match(args)

    return url, server, filename

def process_wget(args) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Process wget command arguments to extract URLs and filenames."""
    url = None
    server = None
    filename = None

    # wget uses '-r' to specify remote filename
    if '-r' in args:
        ip_match = ip_pattern.search(args)
        if ip_match:
            server = ip_match.group()
            if is_invalid_ip(server):
                return None, None, None
            
        remote_filename = remote_filename_pattern.search(args) # '-r filename' extraction
        if remote_filename:
            filename = remote_filename.group(1).split("/")[-1] # Extracts filename from remote file path
    else:
        # Process URL-like patterns in wget arguments
        url, server, filename = process_url_match(args)
    
    return url, server, filename

def process_tftp(args) -> Tuple[Optional[str], Optional[str]]:
    """Process tftp command arguments to extract server and remote file."""
    server = None
    filename = None

    # Extract the server IP or domain from the tftp command
    ip_match = ip_pattern.search(args)
    if ip_match:
        server = ip_match.group()
        if is_invalid_ip(server):
            return None, None

        remote_filename = remote_filename_pattern.search(args) # '-r filename' extraction
        if remote_filename:
            filename = remote_filename.group(1).split("/")[-1] # Extracts filename from remote file path
        else: # '-c get filename' alternative
            alt_get = re.search(r"-c\s+get\s+([^\s;|]+)", args)
            if alt_get:
                filename = alt_get.group(1)

    return server, filename

def process_ftpget(args) -> Tuple[Optional[str], Optional[str]]:
    """Process ftpget command arguments to extract server and remote file."""
    server = None
    filename = None

    ip_match = ip_pattern.search(args)
    if ip_match:
        server = ip_match.group()
        if is_invalid_ip(server):
            return None, None
        # Extract the remote file from the ftpget command
        # Assuming ftpget command is in the format: ftpget <server> <remote_file> <local_file>
        filename = args.split(server, 1)[1].strip(' ').split(' ')[0]

    return server, filename

def update_stats(src_ip, dst_port, command, url, server, filename):
    # Server stats
    if server:
        server_stats[server]["ips"].add(src_ip)
        if filename:
            server_stats[server]["filenames"].add(filename)
        if url:
            server_stats[server]["urls"].add(url)
        server_stats[server]["ports"].add(dst_port)
        server_stats[server]["count"] += 1

    # URL stats
    if url:
        url_stats[url]["src_ips"].add(src_ip)
        if server:
            url_stats[url]["servers"].add(server)
        if filename:
            url_stats[url]["filenames"].add(filename)
        url_stats[url]["ports"].add(dst_port)
        url_stats[url]["count"] += 1

    # Filename stats
    if filename:
        filename_stats[filename]["src_ips"].add(src_ip)
        if server:
            filename_stats[filename]["servers"].add(server)
        if url:
            filename_stats[filename]["urls"].add(url)
        filename_stats[filename]["ports"].add(dst_port)
        filename_stats[filename]["count"] += 1

    # Source IP stats
    if src_ip:
        src_ip_stats[src_ip]["urls"].add(url)
        src_ip_stats[src_ip]["servers"].add(server)
        src_ip_stats[src_ip]["filenames"].add(filename)
        src_ip_stats[src_ip]["ports"].add(dst_port)
        src_ip_stats[src_ip]["count"] += 1

    # Port stats
    if dst_port:
        port_stats[dst_port]["src_ips"].add(src_ip)
        port_stats[dst_port]["urls"].add(url)
        port_stats[dst_port]["servers"].add(server)
        port_stats[dst_port]["filenames"].add(filename)
        port_stats[dst_port]["count"] += 1

    # Command stats
    if command:
        command_stats[command] += 1


#------------------------------ Defining functions for processing ------------------------------#

#------------------------------ Main script execution ------------------------------#

# Process each packet payload from the stdin input CSV file
if len(sys.argv) > 1:
    # Open as gzip if needed
    filename = sys.argv[1]
    if filename.endswith('.gz'):
        infile = gzip.open(filename, 'rt')
    else:
        infile = open(filename, 'r')
else:
    infile = sys.stdin

for line in infile:
# for line in sys.stdin:
    fields = line.strip().split(",")
    if len(fields) < 4:
        continue
    # Extract fields from the CSV line
    src_ip, dst_ip, dst_port, hex_payload = fields

    try:
        # Decode the hex payload into a readable string
        decoded_payload = decode_payload(hex_payload)
        total_payload+=1
        is_malicious = False # flag to track if the payload is malicious

        for command, args in extract_command_chunks(decoded_payload, command_pattern):
            if not args:
                invalid_command+=1
                continue # Skip if no arguments are provided

            url = None
            # A switch-case like 'match' was not used here due to the possibility of executing with python < 3.10
            if command == 'wget':
                url, server, filename = process_wget(args)
            elif command == 'curl':
                url, server, filename = process_curl(args)
            elif command == 'tftp':
                server, filename = process_tftp(args)
            elif command == 'ftpget':
                server, filename = process_ftpget(args)

            if url or server or filename:
                is_malicious = True
                update_stats(src_ip, dst_port, command, url, server, filename)

        if is_malicious:
            malicious_payload += 1

    except Exception as e:
        print(f"Error processing line: {e}")


# TIRAR ISSO AQUI DEPOIS
#***************************************************TIRAR ISSO AQUI DEPOIS***************************************************#
if infile is not sys.stdin:
    infile.close()
#***************************************************TIRAR ISSO AQUI DEPOIS***************************************************#

# Generate overall statistics
top_servers = sorted(server_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
top_urls = sorted(url_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
top_filenames = sorted(filename_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
top_source_ip = sorted(src_ip_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
top_dstport = sorted(port_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
df = pd.DataFrame([
    {
        "Server": server,
        "Count": stats["count"],
        "Distinct IPs": len(stats["ips"]),
        "Distinct Filenames": len(stats["filenames"]),
        "Distinct URLs": len(stats["urls"]),
        "Distinct Ports": len(stats["ports"])
    }
    for server, stats in top_servers
])
df.to_csv("payload_analysis_results/top10_servers.csv", index=False)

# # example:
# # Top servers by count
# top_servers = sorted(server_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
# for server, stats in top_servers:
#     print(server, stats["count"], len(stats["ips"]), len(stats["filenames"]), len(stats["urls"]), len(stats["ports"]))
# # Top servers by count

#------------------------------ Main script execution ------------------------------#

#------------------------------ Saving results to files ------------------------------#

# Create results directory if it doesn't exist
results_dir = os.path.basename(__file__).rstrip('.py') + "_results"
# results_dir = "payload_analysis2_results"
os.makedirs(results_dir, exist_ok=True)

# # Save results for overall statistics
# #------------------------ Save results for all ports -----------------------------#
# with open(os.path.join(results_dir, "url_statistics.csv"), "w") as f:
#     f.write("Most Frequent URLs:\n")
#     f.write("rank,url,count,distinct_ips,ports\n")
#     i = 1
#     for url, count in most_frequent_urls:
#         ports = ", ".join(url_ports_mapping[url])  # Convert ports to a comma-separated string
#         f.write(f"{i},{url},{count},{len(url_ip_mapping[url])},Ports:{ports}\n")
#         i += 1

# with open(os.path.join(results_dir, "filename_statistics.csv"), "w") as f:
#     f.write("Most Frequent Filenames:\n")
#     f.write("rank,filename,count\n")
#     i = 1
#     for filename, count in most_frequent_filenames:
#         f.write(f"{i},{filename},{count}\n")
#         i += 1

# with open(os.path.join(results_dir, "command_statistics.csv"), "w") as f:
#     f.write("Most Frequent Commands:\n")
#     f.write("rank,command,count\n")
#     i = 1
#     for command, count in most_frequent_commands:
#         f.write(f"{i},{command},{count}\n")
#         i += 1
        
# with open(os.path.join(results_dir, "server_statistics.csv"), "w") as f:
#     f.write("Most Frequent Servers:\n")
#     f.write("rank,server,count,distinct_ips\n")
#     i = 1
#     for server, count in most_frequent_servers:
#         f.write(f"{i},{server},{count},{len(server_ip_mapping[server])}\n")
#         i += 1

# with open(os.path.join(results_dir, "port_statistics.csv"), "w") as f:
#     f.write("Most Frequent Ports:\n")
#     f.write("rank,port,count\n")
#     i = 1
#     for port, count in most_frequent_ports:
#         f.write(f"{i},{port},{count}\n")
#         i += 1

# with open(os.path.join(results_dir, "src_ip_statistics.csv"), "w") as f:
#     f.write("Most Frequent Source IPs:\n")
#     f.write("rank,src_ip,count\n")
#     i = 1
#     for src_ip, count in most_frequent_src_ips:
#         f.write(f"{i},{src_ip},{count}\n")
#         i += 1

# #------------------------ Save results for port 23 -----------------------------#
# with open(os.path.join(results_dir, "url_statistics_23.csv"), "w") as f:
#     f.write("Most Frequent URLs (Port 23):\n")
#     f.write("rank,url,count,distinct_ips\n")
#     i = 1

#     for url, count in most_frequent_urls_23:
#         ports = ", ".join(url_ports_mapping_23[url])  # Convert ports to a comma-separated string
#         f.write(f"{i},{url},{count},{len(url_ip_mapping_23[url])}\n")
#         i += 1

# with open(os.path.join(results_dir, "filename_statistics_23.csv"), "w") as f:
#     f.write("Most Frequent Filenames (Port 23):\n")
#     f.write("rank,filename,count,distinct_ips\n")
#     i = 1
#     for filename, count in most_frequent_filenames_23:
#         f.write(f"{i},{filename},{count},{len(filename_ip_mapping_23[filename])}\n")
#         i += 1

# with open(os.path.join(results_dir, "command_statistics_23.csv"), "w") as f:
#     f.write("Most Frequent Commands (Port 23):\n")
#     f.write("rank,command,count\n")
#     i = 1
#     for command, count in most_frequent_commands_23:
#         f.write(f"{i},{command},{count}\n")
#         i += 1

# #------------------------ Save results for NON-port 23 -----------------------------#
# # Save results for non-port 23
# with open(os.path.join(results_dir, "url_statistics_non_23.csv"), "w") as f:
#     f.write("Most Frequent URLs (Non-Port 23):\n")
#     f.write("rank,url,count,distinct_ips\n")
#     i = 1
#     for url, count in most_frequent_urls_non_23:
#         ports = ", ".join(url_ports_mapping_non_23[url])  # Convert ports to a comma-separated string
#         f.write(f"{i},{url},{count},{len(url_ip_mapping_non_23[url])},Ports:{ports}\n")
#         i += 1

# with open(os.path.join(results_dir, "filename_statistics_non_23.csv"), "w") as f:
#     f.write("Most Frequent Filenames (Non-Port 23):\n")
#     f.write("rank,filename,count,distinct_ips\n")
#     i = 1
#     for filename, count in most_frequent_filenames_non_23:
#         f.write(f"{i},{filename},{count},{len(filename_ip_mapping_non_23[filename])}\n")
#         i += 1

# with open(os.path.join(results_dir, "command_statistics_non_23.csv"), "w") as f:
#     f.write("Most Frequent Commands (Non-Port 23):\n")
#     f.write("rank,command,count\n")
#     i = 1
#     for command, count in most_frequent_commands_non_23:
#         f.write(f"{i},{command},{count}\n")
#         i += 1

#--------------------------- Generate latex tables -------------------------------#
def format_number(num) -> str:
    """Format number with thousands separator."""
    return f"{num:,}".replace(',', '.')

def top_urls_by_port(url_stats, port, top_n=10):
    filtered = [
        (url, stats["count"], len(stats["src_ips"]), ", ".join(stats["ports"]))
        for url, stats in url_stats.items()
        if str(port) in stats["ports"]
    ]
    filtered.sort(key=lambda x: x[1], reverse=True)
    return filtered[:top_n]

# Port 23
top_urls_23 = top_urls_by_port(url_stats, 23)
df_urls_23 = pd.DataFrame(top_urls_23, columns=["URL", "Count", "Distinct IPs", "Ports"])
latex_urls_23 = df_urls_23.to_latex(index=False, escape=False, caption="Top 10 URLs (Port 23)", label="tab:top10_urls_23")
with open(os.path.join(results_dir, "top10_urls_23.tex"), "w") as f:
    f.write(latex_urls_23)

# Non-port 23
top_urls_non_23 = [
    (url, stats["count"], len(stats["src_ips"]), ", ".join(stats["ports"]))
    for url, stats in url_stats.items()
    if not ("23" in stats["ports"])
]
top_urls_non_23.sort(key=lambda x: x[1], reverse=True)
df_urls_non_23 = pd.DataFrame(top_urls_non_23[:10], columns=["URL", "Count", "Distinct IPs", "Ports"])
latex_urls_non_23 = df_urls_non_23.to_latex(index=False, escape=False, caption="Top 10 URLs (Non-Port 23)", label="tab:top10_urls_non_23")
with open(os.path.join(results_dir, "top10_urls_non_23.tex"), "w") as f:
    f.write(latex_urls_non_23)


#--------------------------- Generate latex tables -------------------------------#

#--------------------------- Logging summary statistics -------------------------------#
# Print summary
print("Payloads analysis complete!")
print(f"Summary saved to {os.path.join(results_dir, 'payload_analysis_summary.log')}")

with open(os.path.join(results_dir, "payload_analysis_summary.log"), "w") as f:
    f.write("Overall statistics:\n")
    f.write(f"\tPayloads processed: {format_number(total_payload)}\n")
    f.write(f"\tMalicious payloads: {format_number(malicious_payload)} ({malicious_payload / total_payload * 100:.2f}%)\n")
    f.write(f"\tDistinct Source IPs: {format_number(len(src_ip_stats))}\n")
    f.write(f"\tDistinct Destination Ports: {format_number(len(port_stats))}\n")
    f.write(f"\tURLs found: {format_number(len(url_stats))}\n")
    f.write(f"\tFilenames found: {format_number(len(filename_stats))}\n")
    f.write(f"\tServers found: {format_number(len(server_stats))}\n")
    f.write(f"\tCommands found: {format_number(len(command_stats))}\n")

    # Port 23 statistics
    port_23_urls = [url for url, stats in url_stats.items() if "23" in stats["ports"]]
    port_23_servers = [server for server, stats in server_stats.items() if "23" in stats["ports"]]
    port_23_filenames = [fn for fn, stats in filename_stats.items() if "23" in stats["ports"]]
    port_23_src_ips = set()
    for url in port_23_urls:
        port_23_src_ips.update(url_stats[url]["src_ips"])
    port_23_commands = sum(1 for cmd, count in command_stats.items() if cmd and any("23" in port_stats[port]["urls"] for port in port_stats))

    f.write("\nPort 23 statistics:\n")
    f.write(f"\tDistinct Source IPs: {format_number(len(port_23_src_ips))}\n")
    f.write(f"\tURLs found: {format_number(len(port_23_urls))}\n")
    f.write(f"\tServers found: {format_number(len(port_23_servers))}\n")
    f.write(f"\tFilenames found: {format_number(len(port_23_filenames))}\n")
    f.write(f"\tCommands found: {format_number(port_23_commands)}\n")

    # Non-Port 23 statistics
    non23_urls = [url for url, stats in url_stats.items() if "23" not in stats["ports"]]
    non23_servers = [server for server, stats in server_stats.items() if "23" not in stats["ports"]]
    non23_filenames = [fn for fn, stats in filename_stats.items() if "23" not in stats["ports"]]
    non23_src_ips = set()
    for url in non23_urls:
        non23_src_ips.update(url_stats[url]["src_ips"])
    non23_commands = sum(1 for cmd, count in command_stats.items() if cmd and any("23" not in port_stats[port]["urls"] for port in port_stats))

    f.write("\nNon-Port 23 statistics:\n")
    f.write(f"\tDistinct Source IPs: {format_number(len(non23_src_ips))}\n")
    f.write(f"\tURLs found: {format_number(len(non23_urls))}\n")
    f.write(f"\tServers found: {format_number(len(non23_servers))}\n")
    f.write(f"\tFilenames found: {format_number(len(non23_filenames))}\n")
    f.write(f"\tCommands found: {format_number(non23_commands)}\n")