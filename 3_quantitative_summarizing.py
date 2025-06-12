import sys
from datetime import datetime
from collections import Counter, defaultdict

# import seaborn as sns
# import pandas as pd

count_ipsrc={}
count_ipdst={}
count_tcpdstport={}
count_source_country_name={}
count_aws_country_name={}
count_aws_region={}
count_source_country_tcp={}

unknowndstport=0

sources={}
distinct_ip_per_day={}
count_distinct_ips_per_day=defaultdict(int)
distinct_ip_per_source_country=defaultdict(set)

# Initialize a dictionary to store the count of new IPs per day
new_ips_per_day = {}

count_global_stats_transport={}
count_global_stats_mirai_ip_sources={}
count_global_stats_mirai_ip_destinations={}

# line headers:
#   line[0] = timestamp,
#   1 src_ip,
#   2 = dst_ip,
#   3 dst_port, 
#   4 src_iso
#   5 src_country,
#   6 src_longitude,
#   7 src_latitude,
#   8 dst_iso,
#   9 dst_country,
#   10 dst_longitude,
#   11 dst_latitude,
#   12 dst_aws_region

for line in sys.stdin:
    line=line.rstrip()
    line=line.split(',')
    date=str(line[0]).split()[0] # date YY-MM-DD
    ipsrc=str(line[1])
    ipdst=str(line[2])
    tcpdstport=str(line[3])
    source_country_name=str(line[5])
    aws_country_name=str(line[9])
    aws_region=str(line[12])

    # general quantitaive statistics
    if ipsrc in count_ipsrc:
        count_ipsrc[ipsrc] += 1
    else:
        count_ipsrc[ipsrc] = 1

    if ipdst in count_ipdst:
        count_ipdst[ipdst] += 1
    else:
        count_ipdst[ipdst] = 1

    if tcpdstport in count_tcpdstport:
        count_tcpdstport[tcpdstport] += 1
    else:
        count_tcpdstport[tcpdstport] = 1

    if source_country_name in count_source_country_name:
        count_source_country_name[source_country_name] += 1
    else:
        count_source_country_name[source_country_name] = 1

    if aws_country_name in count_aws_country_name:
        count_aws_country_name[aws_country_name] += 1
    else:
        count_aws_country_name[aws_country_name] = 1

    if aws_region in count_aws_region:
        count_aws_region[aws_region] += 1
    else:
        count_aws_region[aws_region] = 1

    if source_country_name not in distinct_ip_per_source_country:
        distinct_ip_per_source_country[source_country_name] = set()
        distinct_ip_per_source_country[source_country_name].add(ipsrc)
    else:
        distinct_ip_per_source_country[source_country_name].add(ipsrc)

    # Anh/Nakamura experiment ('unique' ips per day)
    if date in distinct_ip_per_day:
        # if not (ipsrc in distinct_ip_per_day[date]):
        distinct_ip_per_day[date].add(ipsrc)
    else:
        distinct_ip_per_day[date] = set()
        distinct_ip_per_day[date].add(ipsrc)

    # NOT being used atm
    # # Individual IP statistics
    # if ipsrc not in sources:
    #     sources[ipsrc] = {}
    #     sources[ipsrc][ipdst] = 1
    #     sources[ipsrc][tcpdstport] = 1
    #     sources[ipsrc][aws_country_name] = 1
    #     sources[ipsrc][aws_region] = 1
    # else:
    #     if ipdst not in sources[ipsrc]:
    #         sources[ipsrc][ipdst] = 1
    #     else:
    #         sources[ipsrc][ipdst] += 1

    #     if tcpdstport not in sources[ipsrc]:
    #         sources[ipsrc][tcpdstport] = 1
    #     else:
    #         sources[ipsrc][tcpdstport] += 1

    #     if aws_country_name not in sources[ipsrc]:
    #         sources[ipsrc][aws_country_name] = 1
    #     else:
    #         sources[ipsrc][aws_country_name] += 1
        
    #     if aws_region not in sources[ipsrc]:
    #         sources[ipsrc][aws_region] = 1
    #     else:
    #         sources[ipsrc][aws_region] += 1

# Anh/Nakamura experiment ('new' ips per day)

# Get the sorted list of dates
sorted_dates = sorted(distinct_ip_per_day.keys())
# change date to dd-mm-yyyy format
sorted_dates_formatted = [datetime.strptime(date, "%Y-%m-%d").strftime("%d-%m-%Y") for date in sorted_dates]
# Initialize the first day's new IPs count
new_ips_per_day[sorted_dates_formatted[0]] = len(distinct_ip_per_day[sorted_dates[0]])

# Iterate through the sorted dates, starting from the second day
for i in range(1, len(sorted_dates)):
    current_date = sorted_dates[i]
    previous_date = sorted_dates[i - 1]
    formatted_date = sorted_dates_formatted[i]

    # Get the sets of IPs for the current and previous days
    current_ips = distinct_ip_per_day[current_date]
    previous_ips = distinct_ip_per_day[previous_date]

    # Find new IPs by subtracting the previous day's set from the current day's set
    new_ips = current_ips - previous_ips

    # Store the count of new IPs for the current day
    new_ips_per_day[formatted_date] = len(new_ips)

# # Print the results
# for date, count in new_ips_per_day.items():
#     print(f"Date: {date}, New IPs: {count}")

# count distinct ips per day
for i in range(len(sorted_dates)):
    date = sorted_dates[i]
    formatted_date = sorted_dates_formatted[i]
    distinct_ip_count = len(distinct_ip_per_day[date])
    count_distinct_ips_per_day[formatted_date] = distinct_ip_count

# Count the number of unique IPs per source country
for country, ips in distinct_ip_per_source_country.items():
    count_source_country_tcp[country] = len(ips)

# Overall statistics
count_global_stats_transport['TCP'] = sum(count_tcpdstport.values())
count_global_stats_transport['Unknown'] = unknowndstport
count_global_stats_mirai_ip_sources['IP Sources'] = len(count_ipsrc)
count_global_stats_mirai_ip_destinations['IP Destinations'] = len(count_ipdst)

def percentage(part, whole):
    if whole == 0:
        return 0
    else:
        res = (float(part)) / float(whole)
        return "{:.2%}".format(res)

def genout(d,cname,caption,ranking,sort=True):
    # print("\\newpage")
    label=str(caption)
    filename=label.replace(" ","_") + ".tex"
    label=label.replace(" ","")
    label=label.lower()
    # print("The " + caption + " are shown on Table " + "\\ref{tab:" + label + "}" + ":", file=texfile)
    with open(filename, "w") as texfile:
        print("\\begin{table}[!h]", file=texfile)
        print("\\begin{center}", file=texfile)
        print("\\caption{" + str(caption) + "}", file=texfile)
        print("\\label{tab:" + str(label) + "}", file=texfile)
        print("\\begin{tabular}{ |r|c|c| }", file=texfile)
        print("\\hline", file=texfile)
        print("\\centering " + cname + " & " + "Count" + " & " + "\\%" + "  \\\\", file=texfile)
        print("\\hline", file=texfile)
        if sort:
            result = sorted(d.items(), key=lambda x: x[1], reverse=True)
        else:
            result = d.items()
        total = sum(d.values())
        subtotal = 0
        for key, value in result:
            print(key + " & " + f"{value:,}" + " & " + str(percentage(value, total)).replace("%", "") + "  \\\\", file=texfile)
            subtotal += value
            ranking -= 1
            if ranking == 0:
                break
        print("\\hline", file=texfile)
        print("Sub-total" + " & " + f"{subtotal:,}" + " & " + str(percentage(subtotal, total)).replace("%", "") + "  \\\\", file=texfile)
        print("\\hline", file=texfile)
        print("Total" + " & " + f"{total:,}" + " & " + str(percentage(total, total)).replace("%", "") + "  \\\\", file=texfile)
        print("\\hline", file=texfile)
        print("\\end{tabular}", file=texfile)
        print("\\end{center}", file=texfile)
        print("\\end{table}", file=texfile)
        print("", file=texfile)
    texfile.close()
    

# Unique IP sources and destinations
# genout(count_global_stats_mirai_ip_sources,"Count","Unique Mirai Infected Source IPs",len(count_global_stats_mirai_ip_sources))
# genout(count_global_stats_mirai_ip_destinations,"Count","Unique Mirai Target IPs",len(count_global_stats_mirai_ip_destinations))

# Traffic destined to each AWS region
genout(count_aws_region,"AWS Region","Mirai Scanning Targets (AWS Region)",26)

# Traffic destined to each country
genout(count_aws_country_name,"Country","Top 10 Mirai Scanning Targets (Country)",10)

# Traffic per source country
genout(count_source_country_name,"Country","Top 10 Mirai Scanning Sources (Country)",10)

# TCP destination port rankings
genout(count_tcpdstport,"TCP Port","Top 10 Mirai Scanning Targeted TCP ports",10)

# Daily new infected IPs
genout(new_ips_per_day,"Date","Daily New Infected IPs",47,False)

# Distinct IPs per day
genout(count_distinct_ips_per_day,"Date","Distinct IPs per day",47,False)
# # Distinct IPs per source country
# genout(distinct_ip_per_source_country,"Country","Distinct IPs per Source Country",47,False)

# for i in count_source_country_tcp.keys():
#     merged_source_country_transport_layer[i] = {'TCP',count_source_country_tcp[i]}
# for i in count_source_country_udp.keys():
#     merged_source_country_transport_layer[i] = ['UDP',count_source_country_udp[i]]
# for i in count_source_country_icmp.keys():
#     merged_source_country_transport_layer[i] = ['ICMP',count_source_country_icmp[i]]

# print(merged_source_country_transport_layer)

#### Graph/Chart/Visualization attempts

# merged_source_country_transport_layer={}

# for key,value in count_source_country_name.items():
#     if key in count_source_country_tcp:
#         tcp = count_source_country_tcp[key]
#     else:
#         tcp = 0
#     if key in count_source_country_udp:
#         udp = count_source_country_udp[key]
#     else:
#         udp = 0
#     if key in count_source_country_icmp:
#         icmp = count_source_country_icmp[key]
#     else:
#         icmp = 0
#     merged_source_country_transport_layer[key]=[tcp, udp, icmp]
# print(merged_source_country_transport_layer)



### Graph/Chart/Visualization attempts


# data = pd.DataFrame(merged_source_country_transport_layer)
# # data = pd.DataFrame({'eu-central-2': 337, 'ap-northeast-1': 246, 'ap-south-2': 263})

# heatmap = sns.heatmap(data)
# fig = heatmap.get_figure()
# fig.savefig("heatmap_source_country_transport_layer_protocols.png")

# merged_aws_region_transport_layer={}

# for key,value in count_aws_region.items():
#     if key in count_aws_region_tcp:
#         tcp = count_aws_region_tcp[key]
#     else:
#         tcp = 0
#     if key in count_aws_region_udp:
#         udp = count_aws_region_udp[key]
#     else:
#         udp = 0
#     if key in count_aws_region_icmp:
#         icmp = count_aws_region_icmp[key]
#     else:
#         icmp = 0
#     merged_aws_region_transport_layer[key]=[tcp, udp, icmp]
# print(merged_aws_region_transport_layer)
# print(count_aws_region_tcp)
# data = pd.DataFrame(merged_aws_region_transport_layer)
# # data = pd.DataFrame({'eu-central-2': 337, 'ap-northeast-1': 246, 'ap-south-2': 263})

# heatmap = sns.heatmap(data)
# fig = heatmap.get_figure()
# fig.savefig("heatmap_aws_region_transport_layer_protocols.png")


### Dump raw variables to a dumpfile

# file="summarize_radiation_dict_dump.txt"

# def dumpdict(d,dn):
#     with open(file, 'a') as f:
#         #f.readlines
#         #eof = f.tell()
#         #f.seek(eof)
#         f.write('\n')
#         f.write('Dumping: ' + dn + '\n')
#         result = sorted(d.items(), key=lambda x: x[1], reverse=True)
#         total=sum(d.values())
#         subtotal=0
#         for key,value in result:
#             #print(key + "," + str(value) + "," + percentage(value,total))
#             f.write(key + " & " + f"{value:,}" + " & " + str(percentage(value,total)).replace("%","") + "  \n")
#             subtotal+=value
#         print("Sub-total" + " & " + f"{subtotal:,}" + " & " + str(percentage(subtotal,total)).replace("%","") + "  \n")
#         print("Total" + " & " + f"{total:,}" + " & " + str(percentage(total,total)).replace("%","") + "  \n")
#     f.close


# dumpdict(count_ipsrc, 'count_ipsrc')
# dumpdict(count_ipdst, 'count_ipdst')
# dumpdict(count_tcpdstport, 'count_tcpdstport')
# dumpdict(count_source_country_name, 'count_source_country_name')
# dumpdict(count_aws_country_name, 'count_aws_country_name')
# dumpdict(count_aws_region, 'count_aws_region')
# dumpdict(new_ips_per_day, 'new_ips_per_day')

# #dumpdict(unknowndstport, 'unknowndstport')

# dumpdict(count_global_stats_mirai_ip_sources, 'count_global_stats_mirai_ip_sources')
# dumpdict(count_global_stats_mirai_ip_destinations, 'count_global_stats_mirai_ip_destinations')

