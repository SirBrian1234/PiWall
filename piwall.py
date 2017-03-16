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
from configure import gateway, allowed_internal_hosts, allowed_external_hosts

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
   reason = ''
   
   # first check if ipv4
   if dict_eth['EtherType'] == 'IPv4':     
     
     # this block is both for incoming and outcoming packets and checks whether there is a relation towards a known mac and ip address    
     zero_source_mac = False
     zero_dest_mac = False
     broadcast_source_mac = False
     broadcast_dest_mac = False
     
     gw_source_mac = False
     gw_dest_mac = False     

     known_internal_source_mac = False
     known_internal_dest_mac = False
     known_external_source_mac = False
     known_external_dest_mac = False

     zero_source_ip = False
     zero_dest_ip = False
     broadcast_source_ip = False
     broadcast_dest_ip = False

     gw_source_ip = False
     gw_dest_ip = False

     known_internal_source_ip = False
     known_internal_dest_ip = False     
     known_external_source_ip = False
     known_external_dest_ip = False

     is_source_server = False
     is_dest_server = False
     server_allowed_ports = []
     
     if dict_eth['source'] == 'ff:ff:ff:ff:ff:ff':
        zero_source_mac = True
     elif dict_eth['source'] == 'ff:ff:ff:ff:ff:ff':
        broadcast_source_mac = True

     if dict_eth['destination'] == 'ff:ff:ff:ff:ff:ff':
        zero_dest_mac = True
     elif dict_eth['destination'] == 'ff:ff:ff:ff:ff:ff':
        broadcast_dest_mac = True
     
     if dict_ipv4['source'] == '0.0.0.0':
        zero_source_ip = True
     elif dict_ipv4['source'] == '255.255.255.255':
        broadcast_source_ip = True

     if dict_ipv4['destination'] == '0.0.0.0':
        zero_dest_ip = True
     elif dict_ipv4['destination'] == '255.255.255.255':
        broadcast_dest_ip = True

     if incoming:
        if not zero_source_mac and not broadcast_source_mac:
            if dict_eth['source'] == gateway[0].lower():
               gw_source_mac = True
               if dict_ipv4['source'] == gateway[1]:
                  gw_source_ip = True
            else:
               for i in range (0, len(allowed_external_hosts)):
                  if allowed_external_hosts[i][0].lower()==dict_eth['source']:
                     known_external_source_mac = True
                     if allowed_external_hosts[i][1] == dict_ipv4['source']:
                        known_external_source_ip = True
        
        if not zero_dest_mac and not broadcast_dest_mac:
           for i in range (0, len(allowed_internal_hosts)):
              if allowed_internal_hosts[i][0].lower()==dict_eth['destination']:
                 known_internal_dest_mac = True
                 if allowed_internal_hosts[i][1] == dict_ipv4['destination']:
                    known_internal_dest_ip = True
                    if allowed_internal_hosts[i][2]: # if is server
                       is_dest_server = True
                       server_allowed_ports = allowed_internal_hosts[i][3]
     else:        
        if not zero_dest_mac and not broadcast_dest_mac:
            if dict_eth['destination'] == gateway[0].lower():
               gw_dest_mac = True
               if dict_ipv4['destination'] == gateway[1]:
                  gw_dest_ip = True
            else:
               for i in range (0, len(allowed_external_hosts)):
                  if allowed_external_hosts[i][0].lower()==dict_eth['destination']:
                     known_external_dest_mac = True
                     if allowed_external_hosts[i][1] == dict_ipv4['destination']:
                        known_external_dest_ip = True

        if not zero_source_mac and not broadcast_source_mac:
            for i in range (0, len(allowed_internal_hosts)):
               if allowed_internal_hosts[i][0].lower()==dict_eth['source']:
                  known_internal_source_mac = True
                  if allowed_internal_hosts[i][1] == dict_ipv4['source']:
                     known_internal_source_ip = True
                     if allowed_internal_hosts[i][2]: # if is server
                       is_source_server = True
                       server_allowed_ports = allowed_internal_hosts[i][3]


     if incoming:        
        if gw_source_mac:           
           if not gw_source_ip:           
              # wan packets here
              if known_internal_dest_mac:               
                 if known_internal_dest_ip:                   
                    if dict_ipv4['Protocol'] == 'UDP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['destination']):
                                return True
                          reason = dict_ipv4['Protocol']+': verified server '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                       elif int(dict_transport['destination']) >= 1024:
                          return True   
                       else:
                          reason = dict_ipv4['Protocol']+': non-server host '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                    elif dict_ipv4['Protocol'] == 'TCP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['destination']):
                                return True
                          reason = dict_ipv4['Protocol']+': verified server '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                       elif int(dict_transport['destination']) >= 1024:
                          return True
                       else:
                          reason = dict_ipv4['Protocol']+': non-server host '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                    else:
                       reason = 'Non allowed transport protocol detected '+dict_ipv4['Protocol']+" from "+dict_ipv4['source']
                 else:
                    reason = 'Received peculiar packet from GW for non allowed ip addr'+dict_ipv4['destination']
              else:
                  reason = 'Received peculiar frame from GW with non allowed destination mac '+dict_eth['destination']
           else:
              # packet from host/gw and not from wan
              if dict_ipv4['Protocol'] == 'UDP':
                 for i in range (0, len(gateway[2])):
                    if gateway[2][i] == int(dict_transport['source']):                       
                       verbose("Received IP/UDP datagramm from host/GW protocol of source "+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                       return True
                 reason = "Dropped non-allowed IP/UDP datagramm sent from host/gw of source "+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
              elif dict_ipv4['Protocol'] == 'TCP':
                 for i in range (0, len(gateway[2])):
                    if gateway[2][i] == int(dict_transport['source']):
                       verbose("Received IP/TCP segment from host/GW protocol of source "+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                       return True
                 reason = "Dropped non-allowed IP/TCP segment sent from host/gw of source "+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
              else:
                 reason = "Dropped received IP packet from host/GW of non-allowed transport protocol ["+dict_ipv4['Protocol']+"] for "+dict_eth['destination']+'/'+dict_ipv4['destination']
        elif known_external_source_mac:
           if known_external_source_ip:
              # packet from a known external host
              if known_internal_dest_mac:
                 if known_internal_dest_ip:
                    if dict_ipv4['Protocol'] == 'UDP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['destination']):
                                return True
                          reason = dict_ipv4['Protocol']+': verified server '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                       elif int(dict_transport['destination']) >= 1024:
                          return True
                       else:
                          reason = dict_ipv4['Protocol']+': non-server host '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                    elif dict_ipv4['Protocol'] == 'TCP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['destination']):
                                return True
                          reason = dict_ipv4['Protocol']+': verified server '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                       elif int(dict_transport['destination']) >= 1024:
                          return True
                       else:
                          reason = dict_ipv4['Protocol']+': non-server host '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                    else:
                       reason = 'Non allowed transport protocol detected '+dict_ipv4['Protocol']+" from "+dict_eth['source']+'/'+dict_ipv4['source']          
                 else:
                    reason = 'Wan ip addr '+dict_ipv4['source']+' attempted to connect to non-allowed dest ip addr '+dict_ipv4['destination']
              elif broadcast_dest_mac:
                 reason = 'Outer allowed host attempted to broadcast from external, non gw, host '+dict_eth['source']
              else:
                 reason = 'Outer allowed host attempted to connect to non-allowed inner host '+dict_eth['destination']
           else:
              reason = 'Could not verify known mac-to-ip relation for allowed external source mac ['+dict_eth['source']+'] carrying ip ['+dict_ipv4['source']+']'                
        else:
           reason = 'Outer non allowed host ['+dict_eth['source']+'] attempted to send to inner host ['+dict_eth['destination']+']'     
     
     # outcoming
     else:
        #under dev        
        return True

     # dhcp packets
     if dict_ipv4['Protocol'] == 'UDP':
        if (dict_transport['source']=='67' or dict_transport['source']=='68') and (dict_transport['destination']=='67' or dict_transport['destination']=='68'):
           verbose('DHCP packet fired from '+dict_eth['source']+' to '+dict_eth['destination'],1)
           return True

   # then check if arp
   # all arps allowed
   elif dict_eth['EtherType'] == 'ARP':
      verbose('ARP frame fired from '+dict_eth['source']+' to '+dict_eth['destination'],1)
      return True         
   else:
      reason = 'Non-allowed EtherType ['+dict_eth['EtherType']+'] from ['+dict_eth['source']+'].'

   if incoming:
      dest = "Incoming"
   else:
      dest = "Outcoming"
   
   verbose(dest+" frame no ["+str(frame_id)+"] was denied\n"+reason,1)
   return False

def modify(frame):
   modify = False
   # this part is for you!!!
   # after you change a packet, you have to regenerate packet and frame checksums
   # first regenerate ip packet csm
   # then build ip packet with its csm and include it to frame
   # finaly regenerate frame csm and include to frame
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
   return {'source':s_source, 'destination':s_destination}

def get_tcp_dict(hex_str_frame):
   source = hex_str_frame[68:68+4]
   s_source = str(int(source,16))
   destination = hex_str_frame[68+4:68+4+4]
   s_destination = str(int(destination,16))
   return {'source':s_source, 'destination':s_destination}   

# incoming/outcoming traffic   
def from_ethA_to_ethB(s1,s2,incoming):
   print("started "+str(incoming))
   frame_id = 0 
   while True:
      frame = s1.recvfrom(65565)[0]
      hex_str_frame = binascii.hexlify(frame).decode('ascii')       
      dict_eth = get_ethernet_dict(hex_str_frame)
      dict_ipv4 = {}
      dict_transport = {}
      if dict_eth['EtherType'] == 'IPv4':
         dict_ipv4 = get_ipv4_dict(hex_str_frame)
         if dict_ipv4['Protocol'] == 'UDP':
            dict_transport = get_udp_dict(hex_str_frame)                        
         elif dict_ipv4['Protocol'] == 'TCP':
            dict_transport = get_tcp_dict(hex_str_frame)
      monitor(frame_id,incoming,hex_str_frame,dict_eth,dict_ipv4,dict_transport)
      if firewall(frame_id, incoming, hex_str_frame, dict_eth, dict_ipv4, dict_transport):
         s2.send(modify(frame))
      frame_id = frame_id + 1

try:
   s1 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   s2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   s1.bind(("eth1", 0))
   s2.bind(("eth2", 0))   
   eth1_is_the_external_network = True # if eth2 is the external net do not modify the function calls change this instead
   _thread.start_new_thread( from_ethA_to_ethB, (s1,s2,eth1_is_the_external_network, ))
   from_ethA_to_ethB(s2,s1,not eth1_is_the_external_network)
except:
   raise
