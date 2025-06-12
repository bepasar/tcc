
# Credits:
#   - Original script by @Fabricio Bortoluzzi
#   - Adapted by @Bernardo Pasa Ribeiro

# Description:
#   This script processes pcap files in the current directory, extracting specific 
#   packet information about Mirai botnet infected devices, and and saving it to a CSV file. 
#   It uses tshark for packet analysis and awk for data formatting.

#   The tshark display filters applied to detect the 'Mirai signature' are:
#       Condition 1: filters TCP packets with only the SYN flag activated
#           Expression: (tcp.flags == 0x0002)

#       Condition 2: filters packets with matching TCP raw sequence number and destination IP addresses
#           Expression: (frame[30-33] == frame[38-41])

#   The output is saved in a gzipped CSV file named "output.csv.gz" in the current directory.

# Prerequisites:
#   - tshark (part of the Wireshark suite) must be installed and available in the system PATH.
#   - awk must be installed and available in the system PATH.
#   - gzip must be installed and available in the system PATH.

# Usage: 
#   Place this script in the directory containing the pcap file(s) and run it. OR change
#   to the directory containing the pcap file(s) and then run the script from its path.


# Count the number of .pcap.gz files in the folder
file_count=$(ls -1 *.pcap.gz 2>/dev/null | wc -l)

if [ "$file_count" -eq 0 ]; then
    echo "No .pcap.gz files found in the current directory."
    # exit 1
else
    echo "Found $file_count '*.pcap.gz' files to process."
fi


# Set the maximum number of parallel jobs, if dealing with multiple files
# For maximum performance, adjust accordingly to your machine number of processor/threads
# Hint: you can find out how many available cores with the following command:
#   lscpu | grep "CPU(s)"
max_jobs=3 
job_count=0

# Seting tshark variables
# Note: The batch size is the number of packets to process at once.
#       The buffer size is the amount of memory to use for buffering packets.
#       Adjust these values based on your system's capabilities and the size of the pcap files.
#       A larger batch size may improve performance, but requires more memory.
#       A smaller batch size may reduce memory usage, but may be slower.
# Hint: every 1M packets takes around 1GB of RAM, so adjust accordingly.
batch_size=100000  # Batch size in packets (Value of the -M argument)
buffer_size=128  # Buffer size in MB (value of the -B argument)

# Defining tshark's display filters
filter_tcp_syn="(tcp.flags == 0x0002)" # only TCP syn flag activated
filter_mirai_signature="(frame[30-33] == frame[38-41])" # tcp.seq == ip.dst
filter_mirai_signature_and_tcp_syn="($filter_mirai_signature and $filter_tcp_syn)"

# filter_payloads_download_commands_urls='(tcp.payload matches "http(?!/)" and ((tcp.payload contains "wget") or (tcp.payload matches "curl(?!/)")))'
filter_payloads_download_commands_urls='(tcp.payload matches "wget(?!;)" or tcp.payload matches "curl(?!/)")'

# Function to filter packets
filter_packets() {
    local f="$1"
    local filtered_pcap="$2"
    log_file="progress_${f%.pcap.gz}.log"

    # Step 1: Filter all packets matching the combined filters into a new .pcap file
    display_filter="$filter_mirai_signature_and_tcp_syn or $filter_payloads_download_commands_urls"
    local processed_packets=0

    # 2>&1 is used to redirect both stdout and stderr to the same output stream
    # --log-level "critical" suppresses non-critical messages from tshark
    # awk is used to filter out the "resetting session" lines from the output
    nice -n 10 stdbuf -oL tshark -r "$f" -n -B "$buffer_size" -M "$batch_size" \
        -Y "$display_filter" -w "$filtered_pcap" --log-level "critical" 2>&1 | \
    awk -v batch_size="$batch_size" -v processed_packets="$processed_packets" '
        /resetting session/ {
            processed_packets += batch_size;
            printf "Processed %d packets so far...", , processed_packets > "/dev/stderr";
            next;
        }'
}

# Process files dynamically
echo "Step 1: Filtering packets from .pcap.gz files with $max_jobs jobs in parallel" 
files_done=0
for f in *.pcap.gz; do

	# Derive the name of the filtered file
    filtered_pcap="${f%.pcap.gz}_filtered.pcap"
    
    if [[ -f "$filtered_pcap" ]]; then
        echo "Skipping $f as its filtered file already exists."
        continue  # Skip processing this file
    fi
	
    # Pass the log file to filter_packets
    filter_packets "$f" "$filtered_pcap" > "$log_file" 2>&1 &
    ((job_count++))

    # Wait for any job to finish if max_jobs is reached
    if ((job_count >= max_jobs)); then
        wait -n  # Wait for the next job to finish
        ((job_count--))
        ((files_done++))
        echo "Done processing file $f. Progress: $files_done/$file_count '.pcap.gz' files."
    fi
done

# Wait for any remaining background jobs to finish
while ((job_count > 0)); do
    wait -n
    ((job_count--))
    ((files_done++))
    echo "Progress: $files_done/$file_count .pcap.gz files processed."
done

echo "Step 1: Done filtering from the $file_count '.pcap.gz files."
echo #\n

echo "Step 2: Merging all filtered packets into a single file"
# Step 2: Merge all filtered .pcap files into one and remove the individual files
merged_extension="_regions_mirai.pcap"
combined_pcap="${file_count}${merged_extension}"

# Check if any file matching the pattern exists
matching_files=$(ls *"$merged_extension" 2>/dev/null)
# Check if the variable is not empty
if [[ -n "$matching_files" ]]; then
    echo "The following file(s) matching the pattern '*$merged_extension' already exists:"
    echo "$matching_files"
    echo "Step 2: Merging aborted."
else
	# Combine all filtered .pcap files into one
	mergecap -w $combined_pcap *_filtered.pcap
	echo "Step 2: Merging done. Filtered packets saved to '$combined_pcap'"
	
    # Uncomment the following line to remove individual filtered .pcap files
	# echo "Removing individual filtered .pcap files"
	# rm *_filtered.pcap
fi
echo #\n

# Pre-step 3: Check if the combined pcap file exists
if [[ ! -f "$combined_pcap" ]]; then
    echo "Combined pcap file '$combined_pcap' does not exist. Exiting."
    exit 1
fi

# Pre-step 3: Check if the extraction files already exist
# Initialize flags for extraction
mirai_signature_extraction=0 # flag to check if the extraction was already done
mirai_signature_output_csv="${combined_pcap%.pcap}_signature_packets.output.csv.gz"
if ls *".output.csv.gz" &>/dev/null; then
    echo "The following file(s) matching the pattern '_signature_packets.output.csv.gz' already exists:"
	ls *"_signature_packets.output.csv.gz"
else
    mirai_signature_extraction=1
fi

# Initialize flags for payload extraction
mirai_payload_extraction=0 # flag to check if the extraction was already done
mirai_payload_output_csv="${combined_pcap%.pcap}_payloads.output.csv.gz" # Define the output file name
if ls *"_mirai_payloads.output.csv.gz" &>/dev/null; then
    echo "The following file(s) matching the pattern '_mirai_payloads.output.csv.gz' already exists:"
	ls *"_mirai_payloads.output.csv.gz"
else
    mirai_payload_extraction=1
fi

# Function to extract packets with Mirai signature and payloads
extract_signature_packets() {
    local log_file="progress_signature.log"
    echo "Generating '$mirai_signature_output_csv'..."
    stdbuf -oL tshark -r "$combined_pcap" -n -B "$buffer_size" -M "$batch_size" \
        -Y "$filter_mirai_signature_and_tcp_syn" \
        -t ud -T fields -e _ws.col.Time -e ip.src -e ip.dst -e tcp.dstport -Eseparator=, --log-level "critical" 2>/dev/null | \
    awk '{
        # convert date from YYYY-MM-DD format to DD-MM-YYYY
        split($0, a, "-");                      # split the date and time into separate variables
        split(a[3],b," ");                      # split the date fields into b[]
        print b[1] "-" a[2] "-" a[1] " " b[2]   # print the date fields followed by the in the format DD-MM-YYYY HH:MM:SS
        n = 10000;
        count++;
        if (count % n == 0) {
            # Overwrite the log file with the latest progress
            printf "Extracted data from %d packets so far...\n", count > "progress_signature.log";
        } 
    } END {
            printf "Total packets processed: %d\n", count > "progress_signature.log";
    }' | gzip -c > "$mirai_signature_output_csv" 2>>"$log_file"
    echo "Data from tcp-syn mirai signature packets extracted to '$mirai_signature_output_csv'"
}

# Function to extract packets with suspicious payloads (e.g., wget, curl)
extract_payload_packets() {
    local log_file="progress_payload.log"
    echo "Generating '$mirai_payload_output_csv'..."
    stdbuf -oL tshark -r "$combined_pcap" -n -B "$buffer_size" -M "$batch_size" \
        -Y "$filter_payloads_download_commands_urls" \
        -t ud -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.payload -Eseparator=, --log-level "critical" 2>/dev/null | \
    awk '{
        print $0;
        n = 10000;
        count++;
        if (count % n == 0) {
            # Overwrite the log file with the latest progress
            printf "Extracted data from %d packets so far...\n", count > "progress_payload.log";
        } 
    } END {
        printf "\rTotal packets processed: %d\n", count > "progress_payload.log";
    }' | gzip -c > "$mirai_payload_output_csv" 2>>"$log_file"
    echo "Data from packets with suspicious payload extracted to '$mirai_payload_output_csv'"
}

# Step 3: Extract data for the mirai signature packets and payload download packets 
#         from the filtered .pcap file into separate CSV files, in parallel if both flags are set
echo "Step 3: Extracting data from $combined_pcap"
if [[ $mirai_signature_extraction -eq 1 && $mirai_payload_extraction -eq 1 ]]; then
    extract_signature_packets &
    extract_payload_packets &
    wait  # Wait for both jobs to finish
    echo "Step 3: Data extractions from PCAP to CSV completed."
elif [[ $mirai_signature_extraction -eq 1 ]]; then
    extract_signature_packets
elif [[ $mirai_payload_extraction -eq 1 ]]; then
    extract_payload_packets
else
    echo "Step 3: No extractions were performed."
fi

echo #\n
echo "Mirai extraction process finished!"

# Side notes:
#   The 'stdbuf -oL' command disables output buffering for tshark (ex: resetting session), 
#   ensuring that each line of output is flushed immediately.
#   This allows awk to receive data line by line, so it can update the progress counter
#   and print the progress from processed packets dynamically.

#   Flags/commands breakdown:
#    'nice -n 10' flag sets the process priority to a lower value than standard, allowing other processes to run more smoothly.
#    -n flag in tshark disables name resolution, which can speed up processing.
#    -B 64 flag sets the buffer size to 64 (M or K?)B, which can help with performance.
#    -M "$batch_size" flag sets the maximum number of packets to process at once, which can help with performance.
#    -Y flag applies the display filter to only show packets that match the specified conditions.
#    -t ud flag sets the output format to show the UTC time of each packet.
#    -T fields flag specifies that the output should be in field format.
#    -e flag specifies the fields to include in the output.
#    -Eseparator=, flag specifies that the fields should be separated by commas.
#    --log-level "critical" flag suppresses non-critical messages from tshark.
#    2>/dev/null part suppresses error messages from tshark.
#    gzip -c part compresses the output and writes it to a gzipped CSV file.
#    >> operator appends the output to the specified file.
#    "${f%.pcap}_mirai_output.csv.gz" part creates a gzipped CSV file with the same name as the input pcap file.
#    "${f%.pcap}" part removes the .pcap extension from the filename.
#    .gz extension is added to the output file to indicate that it is gzipped.
#    final output file will be named "output.csv.gz" and will contain the extracted data from the pcap file.
#    script will overwrite the output file if it already exists and also create a backup of the previous output file
#    with the name "_mirai_output.csv.gz.old" and "_mirai_output.csv.old" if any of those exists.