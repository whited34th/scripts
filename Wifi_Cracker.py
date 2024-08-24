'''
WiFi cracker 
WPS WPA WPA2 WPA3 (personal and enterprise versions)
1 scan the surroundings 
2 capture the handshake 
3 crack the passwd 
4 save the file 

functions 
- scan()
    - passive and active scanning
    - passive scan - listens to the packets on the given channel 
    - put network card into monitor mode or assumes that is already put into monitor mode 
    - Active scan - send out probes these packets are used by clients 
    
    Evading active scan 
    - they only process two major packets probe replies and beacons so AP has to hide from two different techniques to hide from active scanner 
    - not responding to the probes that are sent to the SSID 
    - disable beacons but beacons not only used for advertising the network also have other functions 
- capture()
- crack_passwd()*
'''

'''
WPA - WiFi Protected Access is security standard for computing devices equipped with Wireless internet connection
- Released in 2003 by the WiFi Alliance
- WPA works using two modes for personal and enterprise use
- personal - WPA-PSK 
- enterprise - WPA-EAP requires authentication server 
- WPA uses RC4 cipher with longer IVs and 256 bit keys and TKIP 
- WPA2 uses counter mode cipher block chaining message authentication code protocol (CCMP) which is based on AES (Advanced Encryption Standard) algorithm

wifi is subset of 802.11 standard 
- 802.11 creates wireless access to wired networks with use of AP(access points) refferes as ad-hoc or IBSS 
- 802.11 standard divides all packtes into three different categories : data, management and control 
- data packets are used to carry higher level data IP packets, management packets control management and control packets used to mediating access to shared memory and
- packet have subtypes - Beacons and Deauthentication packets are management packets subtypes
- Request to send(RTS) and Clear to send(CTS) are control packets subtypes
- 802.11 has three address - source, destination and BSSID (Basic service set ID)
- BSSID identifies AP and collection of associated stations and it is often same MAC address as wireless interface on the AP 
- 802.11 Security primer - WEP(Wired Equivalency protocol) and WPA(Wifi protected access)
- WPA has two modes - WPA-PSK : Per-shared key and enterprise mode 

WPA-PSK 
- Passpharse : 8-63 printable ASCII characters   
- SSID : Service set identifier or your wifi name 

- kismet 
- aircrack-ng suite 
- aireplay-ng suite 

'''

'''

Dot11beacon is a class that represents an 802.11 Beacon Frame, Beacon Frames are used to advertise the presece of the AP's (Access Points)

'''

from scapy.all import *
import pandas as pd

# Initialize the DataFrame
ntwrks = pd.DataFrame(columns=['BSSID', 'SSID', 'dBm_signal', 'channel', 'wifi_type']).set_index('BSSID')

def get_info(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else 'Hidden SSID'
        dBm_signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'
        channel = ord(pkt[Dot11Elt:3].info) if pkt[Dot11Elt:3].info else 'N/A'
        
        return {
            'BSSID': bssid,
            'SSID': ssid,
            'dBm_signal': dBm_signal,
            'channel': channel
        }
    return None

def packet_handler(pkt):
    info = get_info(pkt)
    if info:
        ntwrks.loc[info['BSSID']] = [info['SSID'], info['dBm_signal'], info['channel'], 'WPA/WPA2']

# Example usage: sniffing packets
sniff(iface='wlan0mon', prn=packet_handler, store=0)