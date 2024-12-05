import re
from datetime import datetime, timedelta
import time


logdata = [
    "2022-07-29 10:15:00 192.168.5.10 10.0.0.5 80 ALLOW",
    "2022-07-29 10:15:05 192.168.6.11 10.0.0.5 80 ALLOW",
    "2022-07-29 10:15:10 192.168.7.12 10.0.0.5 22 DENY",
    "2022-07-29 10:15:15 192.168.8.13 10.0.0.5 22 DENY",
    "2022-07-29 10:15:20 192.168.9.10 10.0.0.6 443 ALLOW",
]

denyentries = []

#fopen = open("logs.log", "r")

for line in logdata:
    
    if re.search("DENY", line):
        #print(line.strip())
        parts = line.split()
        #action = parts[-1]
        #print(parts)
        timestampstr = f"{parts[0]} {parts[1]}"
        timestamp = datetime.strptime(timestampstr, '%Y-%m-%d %H:%M:%S')
        source_ips = parts[2]
        denyentries.append((timestamp, source_ips))
        #print(denyentries)

        for i in range(len(denyentries)):
            for j in range(i+1, len(denyentries)):
                #print(denyentries[i][0])
                #print(denyentries[j][0])
                if denyentries[j][0] <= denyentries[i][0] + timedelta(minutes=10):
                    print(f"DENY entry from source IP: {denyentries[i][1]} and & {denyentries[j][1]} are within 10 minutes")
                
