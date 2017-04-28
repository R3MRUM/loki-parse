# loki-parse
A python script that can detect and parse loki-bot (malware) related network traffic between a compromised host and a C2 server. This script can be helpful to DFIR analysts and security researchers who want to know what data is being exfiltrated to the C2, bot tracking, etc...

This script can either sniff the wire directly (no switch) or read in a PCAP of network traffic (using --pcap $pcap_file) . When the script detects loki-bot related network traffic, it will dump out the data contained within the packets out to the screen in JSON format.

Some of the packets contain data being exfiltrated that is compressed with aPLib. The script will decompress that data and display it to your screen but know that there is additional processing that has not been incorporated into this script...YET. This being said, <b>it is important that you also download the aplib.py script and keep it in the same directory as loki-parse.py</b>. This script is required in order for loki-parse to execute successfully.

Finally, there is an issue with the code used for sniffing network traffic where the data portion of the packet can get chopped off. It appears to be related to how scapy parses the traffic. This will likely happen with larger packets that have compressed data. If this happens, the following dictionary key will be created:

<b>Decompressed Application/Credential Data': 'ERROR: Incomplete Packet Detected</b>

This issue does not seem to occur within saved PCAPs so, if you receive this error, try saving the network traffic into a pcap file and rerunning loki-parse on the pcap.

If the script is able to successfully decompress the data within the packet, this data is simply dumped to the screen (not in JSON format). I plan to address this in later versions.

I've provided <b>loki-bot_network_traffic.pcap</b> as an example pcap for you to play with.

# Example Output
<b>$ sudo ./loki_parse.py</b>
Sniffing PCAPS from the wire
```json
{
    "64bit OS": false, 
    "Bot ID (0)": "XXXXX11111", 
    "Built-In Admin": true, 
    "Compressed Application/Credential Data Size (Bytes)": 2310, 
    "Data Compressed": true, 
    "Decompressed Application/Credential Data": "ERROR: Incomplete Packet Detected", 
    "Domain Hostname (1)": "REMWorkstation", 
    "First Transmission": true, 
    "Hidden File [Hash Database]": "%APPDATA%\\C98066\\6B250D.hdb", 
    "Hidden File [Keylogger Database]": "%APPDATA%\\C98066\\6B250D.kdb", 
    "Hidden File [Lock File]": "%APPDATA%\\C98066\\6B250D.lck", 
    "Hidden File [Malware Exe]": "%APPDATA%\\C98066\\6B250D.exe", 
    "Hostname (1)": "REMWORKSTATION", 
    "Local Admin": true, 
    "Mutex (1)": "B7E1C2CC98066B250DDB2123", 
    "Operating System": "Windows 8.1 Workstation", 
    "Original Application/Credential Data Size (Bytes)": 8545, 
    "Packet Info - Data Transmission Time": "2017-04-28T17:00:55.331980", 
    "Packet Info - Destination IP": "185.141.27.187", 
    "Packet Info - Destination Port": 80, 
    "Packet Info - Source IP": "172.16.0.130", 
    "Packet Info - Source Port": 49401, 
    "Payload Type": "Application/Credential Data", 
    "Screen Resolution": "1920x1080", 
    "Unique Key": "oKUl1", 
    "User Name (1)": "REM", 
    "Version": 1.8
}
```
