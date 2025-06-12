'''
Usage:
cat *.csv | python3 /path/to/this/script/2_mirai_enrich_csv.py | gzip > *.rich.csv.gz
zcat *.csv.gz | python3 /path/to/this/script/2_mirai_enrich_csv.py | gzip > *.rich.csv.gz
'''
import sys
import geoip2.database
# solver = geoip2.database.Reader('/home/bepasar/cco/tcc/demo_ibr/raw/aggregated/GeoLite2-City.mmdb') #FREE
# solver = geoip2.database.Reader('GeoIP2-City.mmdb') #LICENSED
solver = geoip2.database.Reader('/mnt/s/IBR/dataset_IBR/maxmind_geolite/GeoIP2-City_12_2023.mmdb') #LICENSED
import awsipranges
aws_ip_ranges = awsipranges.get_ranges()
cachesrc={}
cachedst={}
cachesrchit=0
cachesrcmiss=0
cachedsthit=0
cachedstmiss=0
cacheinfo=open("cacheinfo.txt","w")
anomalous_entries=open("anomalous_entries.csv","w")
   
for rawline in sys.stdin:
     
    line=rawline.rstrip().split(',')
    if len(line) == 4 and len(line[1].split('.')) == 4 and len(line[2].split('.')) == 4: #DIRTY IP CHECK
        timestamp=str(line[0])
        ipsrc=str(line[1])
        ipdst=str(line[2])
        tcpdstport=str(line[3])

        if not ipsrc in cachesrc.keys():
            cachesrcmiss+=1
            try:
                geoip_source = solver.city(ipsrc)
            except:
                cachesrc[ipsrc] = {}
                cachesrc[ipsrc]['iso_code'] = "ZZ" #6
                cachesrc[ipsrc]['country_name'] = "Unknown Country" #7
                cachesrc[ipsrc]['latitude'] = "-99" #9 
                cachesrc[ipsrc]['longitude'] = "-99" #10
            else:
                cachesrc[ipsrc] = {}
                cachesrc[ipsrc]['iso_code'] = str(geoip_source.country.iso_code)#6
                cachesrc[ipsrc]['country_name'] = str(geoip_source.country.name).replace(",","")#7
                cachesrc[ipsrc]['latitude'] = str(geoip_source.location.latitude)#9
                cachesrc[ipsrc]['longitude'] = str(geoip_source.location.longitude)#10
                 
        else:
             cachesrchit+=1

        line.append(cachesrc[ipsrc]['iso_code']) #7
        source_country_iso_code=cachesrc[ipsrc]['iso_code']#7
        line.append(cachesrc[ipsrc]['country_name'])#8
        source_country_name=cachesrc[ipsrc]['country_name']#8
        line.append(cachesrc[ipsrc]['latitude'])#10
        source_latitude=cachesrc[ipsrc]['latitude']#10
        line.append(cachesrc[ipsrc]['longitude'])#11
        source_longitude=cachesrc[ipsrc]['longitude']#11

        if not ipdst in cachedst.keys():
            cachedstmiss+=1
            try:
                geoip_destination = solver.city(ipdst)
            except:
                cachedst[ipdst] = {}
                cachedst[ipdst]['iso_code'] = "ZZ" #12
                cachedst[ipdst]['country_name'] = "Unknown Country" #13
                cachedst[ipdst]['latitude'] = "-99" #15
                cachedst[ipdst]['longitude'] = "-99" #16
            else:
                cachedst[ipdst] = {}
                cachedst[ipdst]['iso_code'] = str(geoip_destination.country.iso_code)#12
                cachedst[ipdst]['country_name'] = str(geoip_destination.country.name).replace(",","")#13
                cachedst[ipdst]['latitude'] = str(geoip_destination.location.latitude)#15
                cachedst[ipdst]['longitude'] = str(geoip_destination.location.longitude)#16

                try:
                    aws_response = aws_ip_ranges.get(ipdst)
                    cachedst[ipdst]['region'] = str(aws_response.region)
                except:
                    cachedst[ipdst]['region'] = "Unknown" #17
 
        else:
             cachedsthit+=1
                
        line.append(cachedst[ipdst]['iso_code']) #12
        aws_country_code=cachedst[ipdst]['iso_code'] #12
        line.append(cachedst[ipdst]['country_name']) #13
        aws_country_name=cachedst[ipdst]['country_name'] #13
        line.append(cachedst[ipdst]['latitude']) #15
        aws_latitude=cachedst[ipdst]['latitude'] #15
        line.append(cachedst[ipdst]['longitude']) #16
        aws_longitude=cachedst[ipdst]['longitude'] #16
        line.append(cachedst[ipdst]['region']) #17
        aws_region=cachedst[ipdst]['region'] #17
        output=timestamp + "," + ipsrc + "," + ipdst + "," + tcpdstport + "," + source_country_iso_code + "," + source_country_name + "," + source_latitude + "," + source_longitude + "," + aws_country_code + "," + aws_country_name + "," + aws_latitude + "," + aws_longitude + "," + aws_region
    
        print(output)
    else:
        anomalous_entries.write(rawline)

solver.close()
anomalous_entries.close()
                    
cacheinfo.write("Source IP stats" + "" + "\n")
cacheinfo.write("Source IP addresses cached: " + str(len(cachesrc)) + "\n")
cacheinfo.write("Source IP cache hit: " + str(cachesrchit) + "\n")
cacheinfo.write("Source IP cache miss: " + str(cachesrcmiss) + "\n")
cacheinfo.write("\n")
cacheinfo.write("AWS IP stats" + "" + "\n")
cacheinfo.write("AWS IP addresses cached: " + str(len(cachedst)) + "\n")
cacheinfo.write("AWS IP cache hit: " + str(cachedsthit) + "\n")
cacheinfo.write("AWS IP cache miss: " + str(cachedstmiss) + "\n")
cacheinfo.write("\n")
cacheinfo.close()