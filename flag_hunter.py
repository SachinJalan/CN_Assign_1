import re
file = open("logsq2.txt","r",encoding='utf-8',errors='ignore') 
data=file.read()
file.close()
source_port_needed=0
array_data=re.split(r'###########################################################',data)
flags=[]
stream_ip='a'
for i in array_data:
    if re.search(r'Flag:',i) or re.search(r'milkshake',i) or re.search(r'username',i): 
        flags.append(i)
    if(re.search(r'131.144.126.118',i)):
        pattern1 = r'Source Port\s+:\s+(\d+)'
        match1=re.search(pattern1,i)
        pattern2 = r'Destination Port\s+:\s+(\d+)'
        match2=re.search(pattern2,i)
        source_port_needed=str(int(match2.group(1))+int(match1.group(1)))
        string_needed=f'Source Port : {source_port_needed}'
        # print(source_port_needed)
    if source_port_needed!=0 and re.search(re.escape(string_needed),i):
        flags.append(i)
    pattern_csum=r'TCP Checksum\s+:\s+(\d+)'
    match_csum=re.search(pattern_csum,i)
    
    if(match_csum and match_csum.group(1)=='2756'):
        stream_ip=re.search(r'Source\s+IP\s+:\s+(\S+)',i).group(1)

for i in array_data:
    if(stream_ip!='a' and re.search(re.escape(stream_ip),i)):
        if(re.search(r'PASS',i)):
            flags.append(i)
for i in flags[::2]:
    print(i)