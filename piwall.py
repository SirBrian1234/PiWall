"""
piwall.py: Here is the main logic of PiWall and your canvas as well!
You may define any kind of rule to either monitor, firewall or change your traffic.
"""

__author__ = "Konstantinos Kagiampakis"
__license__ = """ 
Creative Commons Attribution 4.0 International
https://creativecommons.org/licenses/by/4.0/
https://creativecommons.org/licenses/by/4.0/legalcode
"""

import socket
import _thread
import time
import sys
import codecs
import binascii
from configure import allowed_external_host_macs, allowed_host_macs, known_ips_to_mac

def verbose(message, type):
  allow_verbose = True
  verbose_level = 2
  h = ''

  if allow_verbose:
     if type == 0 and verbose_level >=0:
        h = '@MODIFY'
        print(h+' '+message)
     elif type == 1 and verbose_level >=1:
        h = '$FIREWALL:'
        print(h+' '+message)
     elif type == 2 and verbose_level >=2:
        h = '*MONITOR:'
        print(h+' '+message)

def monitor(frame_id, incoming, hex_str_frame, dict_eth, dict_ipv4, dict_transport):
   allow_verbose = False
   allow_log = False
   if allow_verbose:
      print('\n['+hex_str_frame+']\n')      

def firewall(frame_id, incoming, hex_str_frame, dict_eth, dict_ipv4, dict_transport):
   allow = False
   reason = ''
   
   #first check if ipv4
   if dict_eth['EtherType'] == 'IPv4':     
     
     # this block is both for incoming and outcoming packets and checks whether there is a relation towards a known mac and ip address
     known_dest_ip = False
     known_source_ip = False
     is_source_server = False
     is_dest_server = False
     found = False         
     for i in range (0, len(known_ips_to_mac)):
       if known_ips_to_mac[i][0].lower()==dict_eth['source'] and known_ips_to_mac[i][1]==dict_ipv4['source']:
          known_source_ip = True
          is_source_server = known_ips_to_mac[i][2]
     if not known_source_ip:
        reason = 'Could not verify known mac-to-ip relation for source mac '+dict_eth['source']+' with ip addr '+dict_ipv4['source']
     
     for i in range (0, len(known_ips_to_mac)):
       if known_ips_to_mac[i][0].lower()==dict_eth['destination'] and known_ips_to_mac[i][1]==dict_ipv4['destination']:
          known_dest_ip = True        
          is_dest_server = known_ips_to_mac[i][2]
     if not known_dest_ip:
        reason = 'Could not verify known mac-to-ip relation for destination mac '+dict_eth['destination']+' with ip addr '+dict_ipv4['destination']

     # from the network ahead our FW we accept to exchange data only with the GW
     # we allow broadcast and zero ips only for the DHCP
     if incoming:
         #print('fw incoming')
         #print (dict_eth['source'])
         #print (dict_eth['destination'])
         found = False
         for i in range (0, len(allowed_external_host_macs)):
            if allowed_external_host_macs[i].lower()==dict_eth['source']:
               found = True

         if found:
            #print (dict_eth['source'])
            #print (dict_eth['destination'])
            found = False
            for i in range (0, len(allowed_host_macs)):
               if allowed_host_macs[i].lower()==dict_eth['destination']:
                  found = True            
            
            if found:  
               if dict_ipv4['Protocol'] == 'UDP':
                  # dhcp needs 0 and 255                
                  if (dict_transport['source']=='67' or dict_transport['source']=='68') and (dict_transport['destination']=='67' or dict_transport['destination']=='68'):
                     allow = True
                  elif known_dest_ip:
                     # now we need to block ports
                     if is_dest_server:
                        allow = True
                     elif int(dict_transport['destination']) >= 6000:
                        allow = True
                     else:                        
                        reason = 'Destination port '+dict_transport['destination']+' is not allowed for a non-server host'

               elif dict_ipv4['Protocol'] == 'TCP':
                   if known_dest_ip:
                     # now we need to block ports for non server and allow ports on servers
                     if is_dest_server:
                        allow = True
                     elif int(dict_transport['destination']) >= 6000:
                        allow = True 
                     else:                     
                        reason = 'Destination port '+dict_transport['destination']+' is not allowed for a non-server host'   
               else:               
                  reason = 'Not allowed transport protocol ['+dict_ipv4['Protocol']+']'
            else: 
               reason = 'Not allowed destination host mac address ['+dict_eth['destination']+']'
         else:            
             reason = 'Outer non allowed host ['+dict_eth['source']+'] attempted to contact inner host'
     
     else:
        #print('fw outcoming') 
        #print (dict_eth['source'])
        #print (dict_eth['destination'])
        found = False
        for i in range (0, len(allowed_external_host_macs)):
           if allowed_external_host_macs[i].lower()==dict_eth['destination']:
              found = True

        if found:
            found = False
            for i in range (0, len(allowed_host_macs)):
               if allowed_host_macs[i].lower()==dict_eth['source']:
                  found = True
            
            if found:
               #print('after mac verify')
               if dict_ipv4['Protocol'] == 'UDP':
                  if dict_transport['source']=='67' or dict_transport['source']=='68':
                     allow = True
                     # from this point on we do not allow special ips. dhcp needs 0 and 255
                  elif known_source_ip:                   
                     if is_source_server:
                        allow = True
                     elif int(dict_transport['source']) >= 6000:
                        allow = True
                     else:                        
                        reason = 'Source port '+dict_transport['source']+' is not allowed for a non-server host'
               elif dict_ipv4['Protocol'] == 'TCP':
                     if known_source_ip:
                        if is_source_server:
                           allow = True
                        elif int(dict_transport['source']) >= 6000:
                           allow = True
                        else:                           
                           reason = 'Source port '+dict_transport['source']+' is not allowed for a non-server host'                                         
               else:
                  allow = False
                  reason = 'Not allowed transport protocol ['+dict_ipv4['Protocol']+']'
            else:
               reason = 'Not allowed source host mac address ['+dict_eth['source']+']'
        else:
            reason = 'Inner network host attempted to communicate with non allowed host on outer network ['+dict_eth['destination']+']'
            
   #All arps allowed
   elif dict_eth['EtherType'] == 'ARP':
      allow = True
   else:
      reason = 'Non-allowed EtherType. '+dict_eth['EtherType']

   if not allow:
      if incoming:
         dest = "Incoming"
      else:
         dest = "Outcoming"
      verbose(dest+" frame no ["+str(frame_id)+"] was denied\n"+reason,1)
   return allow

def modify(frame):
   modify = False
   #at the end you should regenerate checksums
   if modify:
      verbose("The frame was altered",2)
   return frame

def get_ethernet_dict(hex_str_frame):
   dest_mac = hex_str_frame[0:12]
   dest_mac = ':'.join(a+b for a,b in zip(dest_mac[::2], dest_mac[1::2]))
   source_mac = hex_str_frame[12:24]
   source_mac = ':'.join(a+b for a,b in zip(source_mac[::2], source_mac[1::2]))
   EtherType = hex_str_frame[24:28]
   if EtherType == '0800':
      s_EtherType = 'IPv4'
   elif EtherType == '0806':
      s_EtherType = 'ARP'
   else:
      s_EtherType = EtherType   
   return {'source':source_mac,'destination':dest_mac,'EtherType':s_EtherType}
 
def get_ipv4_dict(hex_str_frame):
   header = hex_str_frame[28:28+40]
   version = hex_str_frame[28:28+2]
   protocol = hex_str_frame[28+18:28+18+2]
   source_ip = hex_str_frame[28+18+2+4:28+18+2+4+8]
   destination_ip = hex_str_frame[28+18+2+4+8:28+18+2+4+8+8]
   if protocol == '06':
     s_prot = 'TCP'
   elif protocol == '11':
     s_prot = 'UDP'
   else:
     s_prot = protocol   
   s_source_ip = str(int(source_ip[0:2],16))+'.'+str(int(source_ip[2:4],16))+'.'+str(int(source_ip[4:6],16))+'.'+str(int(source_ip[6:8],16))
   s_dst_ip = str(int(destination_ip[0:2],16))+'.'+str(int(destination_ip[2:4],16))+'.'+str(int(destination_ip[4:6],16))+'.'+str(int(destination_ip[6:8],16))
   return {'Protocol':s_prot,'source':s_source_ip,'destination':s_dst_ip}

def get_udp_dict(hex_str_frame):
   source = hex_str_frame[68:68+4]
   s_source = str(int(source,16))
   destination = hex_str_frame[68+4:68+4+4]
   s_destination = str(int(destination,16))
   #print(s_source)
   #print(s_destination)
   return {'source':s_source, 'destination':s_destination}

def get_tcp_dict(hex_str_frame):
   source = hex_str_frame[68:68+4]
   s_source = str(int(source,16))
   destination = hex_str_frame[68+4:68+4+4]
   s_destination = str(int(destination,16))
   #print(s_source)
   #print(s_destination)
   return {'source':s_source, 'destination':s_destination}   

# incoming traffic   
def from_ethA_to_ethB(s1,s2,incoming):
   print("started "+str(incoming))
   frame_id = 0 
   while True:
      frame = s1.recvfrom(65565)[0]
      hex_str_frame = binascii.hexlify(frame).decode('ascii')       
      dict_eth = get_ethernet_dict(hex_str_frame)
      dict_ipv4 = {}
      dict_transport = {}
      #print('read from eth1')
      #print(dict_eth['EtherType'])
      #print(dict_eth['source'])
      #print(dict_eth['destination'])
      if dict_eth['EtherType'] == 'IPv4':
         dict_ipv4 = get_ipv4_dict(hex_str_frame)
         if dict_ipv4['Protocol'] == 'UDP':
            dict_transport = get_udp_dict(hex_str_frame)
            #print('SOURCE'+dict_transport['source'])
            #print(dict_transport['destination'])
         elif dict_ipv4['Protocol'] == 'TCP':
            dict_transport = get_tcp_dict(hex_str_frame)
            #print(dict_transport['source'])
            #print(dict_transport['destination'])
      monitor(frame_id,incoming,hex_str_frame,dict_eth,dict_ipv4,dict_transport)
      if firewall(frame_id, incoming, hex_str_frame, dict_eth, dict_ipv4, dict_transport):
         s2.send(modify(frame))
      #frame_id = frame_id + 1

try:
   s1 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   s2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   s1.bind(("eth1", 0))
   s2.bind(("eth2", 0))   
   _thread.start_new_thread( from_ethA_to_ethB, (s1,s2,False, ))
   from_ethA_to_ethB(s2,s1,True)
except:
   raise
