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

def monitor(frame_id, allowed_frame_id, incoming, hex_str_frame, dict_eth, dict_ipv4, dict_transport):
   allow_verbose = False
   allow_log = False
   if allow_verbose:
      print('\n['+hex_str_frame+']\n')      

def firewall(frame_id, incoming, hex_str_frame, dict_eth, dict_ipv4, dict_transport):   
   reason = ''
   bc_mac = 'ff:ff:ff:ff:ff:ff'
   zero_mac = '00:00:00:00:00:00' 
   int_pos = -1
   ext_pos = -1

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
   
   if dict_eth['source'] == zero_mac:
      zero_source_mac = True
   elif dict_eth['source'] == bc_mac:
      broadcast_source_mac = True

   if dict_eth['destination'] == zero_mac:
      zero_dest_mac = True
   elif dict_eth['destination'] == bc_mac:
      broadcast_dest_mac = True

   if incoming:
      if not zero_source_mac and not broadcast_source_mac:
          if dict_eth['source'] == gateway[0].lower():
             gw_source_mac = True
             
          else:
             for i in range (0, len(allowed_external_hosts)):
                if allowed_external_hosts[i][0].lower()==dict_eth['source']:
                   known_external_source_mac = True                 
                   ext_pos = i

      if not zero_dest_mac and not broadcast_dest_mac:
         for i in range (0, len(allowed_internal_hosts)):
            if allowed_internal_hosts[i][0].lower()==dict_eth['destination']:
               known_internal_dest_mac = True
               int_pos = i
                                        
   else:
      if not zero_dest_mac and not broadcast_dest_mac:
          if dict_eth['destination'] == gateway[0].lower():
             gw_dest_mac = True
             
          else:
             for i in range (0, len(allowed_external_hosts)):
                if allowed_external_hosts[i][0].lower()==dict_eth['destination']:
                   known_external_dest_mac = True                   
                   ext_pos = i

      if not zero_source_mac and not broadcast_source_mac:
          for i in range (0, len(allowed_internal_hosts)):
             if allowed_internal_hosts[i][0].lower()==dict_eth['source']:
                known_internal_source_mac = True              
                int_pos = i

   # first check if ipv4
   if dict_eth['EtherType'] == 'IPv4':     
     
     # this block is both for incoming and outcoming packets and checks whether there is a relation towards a known mac and ip address       
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
          
     if dict_ipv4['source'] == '0.0.0.0':
        zero_source_ip = True
     elif dict_ipv4['source'] == '255.255.255.255':
        broadcast_source_ip = True

     if dict_ipv4['destination'] == '0.0.0.0':
        zero_dest_ip = True
     elif dict_ipv4['destination'] == '255.255.255.255':
        broadcast_dest_ip = True

     if incoming:
        if gw_source_mac:         
           if dict_ipv4['source'] == gateway[1]:
              gw_source_ip = True
      
        elif known_external_source_mac:
           if allowed_external_hosts[ext_pos][1] == dict_ipv4['source']:
              known_external_source_ip = True
        
        if known_internal_dest_mac:
           if allowed_internal_hosts[int_pos][1] == dict_ipv4['destination']:
              known_internal_dest_ip = True
              if allowed_internal_hosts[int_pos][2]: # if is server
                 is_dest_server = True
                 server_allowed_ports = allowed_internal_hosts[i][3]

     else:        
        if gw_dest_mac:
           if dict_ipv4['destination'] == gateway[1]:
              gw_dest_ip = True

        elif known_external_dest_mac:
           if allowed_external_hosts[ext_pos][1] == dict_ipv4['destination']:
              known_external_dest_ip = True

        if known_internal_source_mac:
           if allowed_internal_hosts[int_pos][1] == dict_ipv4['source']:
              known_internal_source_ip = True
              if allowed_internal_hosts[int_pos][2]: # if is server
                 is_source_server = True
                 server_allowed_ports = allowed_internal_hosts[i][3]
     
     #print('IPv4')
     #print('source '+dict_ipv4['source'])
     #print('dest '+dict_ipv4['destination'])
     #print('broadcast_source_ip '+str(broadcast_source_ip))
     #print('gw_source_ip '+str(gw_source_ip))
     #print('known_external_source_ip '+str(known_external_source_ip))
     #print('known_internal_source_ip '+str(known_internal_source_ip))
     #print()
     #print('broadcast_dest_ip ',str(broadcast_dest_ip))
     #print('gw_dest_ip ',str(gw_dest_ip))
     #print('known_external_dest_ip ',str(known_external_dest_ip))
     #print('known_internal_dest_ip ',str(known_internal_dest_ip))

     if incoming:        
        if known_internal_dest_mac:               
           if known_internal_dest_ip:
              # now we are sure that the packet goes to a verified inner host            
              if gw_source_mac:           
                 if not gw_source_ip:                       
                    #IPv4 WAN Incoming traffic <- towards -> a known internal host                   
                    if dict_ipv4['Protocol'] == 'UDP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['destination']):
                                return True
                          reason = 'WAN incoming traffic '+dict_ipv4['Protocol']+': verified server '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                       elif int(dict_transport['destination']) >= 1024:
                          return True   
                       else:
                          reason = 'WAN incoming traffic '+dict_ipv4['Protocol']+': non-server host '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                    elif dict_ipv4['Protocol'] == 'TCP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['destination']):
                                return True
                          reason = 'WAN incoming traffic '+dict_ipv4['Protocol']+': verified server '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                       elif int(dict_transport['destination']) >= 1024:
                          return True
                       else:
                          reason = 'WAN incoming traffic '+dict_ipv4['Protocol']+': non-server host '+dict_ipv4['destination']+' received request in a non verified port '+dict_transport['destination']+' from wan ip addr '+dict_ipv4['source']
                    else:
                       reason = 'Non allowed transport protocol detected '+dict_ipv4['Protocol']+" from "+dict_ipv4['source']

                 else:                            
                    # Host/GW incoming traffic <- towards -> a known internal host
                    if dict_ipv4['Protocol'] == 'ICMP':
                       verbose('Allowed incoming,  IPv4/ICMP from GW towards '+dict_eth['destination']+'/'+dict_ipv4['destination'],1)
                       return True
                    elif dict_ipv4['Protocol'] == 'UDP':
                       for i in range (0, len(gateway[3])):
                          if gateway[3][i] == int(dict_transport['source']):                       
                             verbose("Allowed incoming,  IPv4/UDP datagramm from host/GW towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                             return True
                       reason = "non-allowed IPv4/UDP datagramm sent from host/gw towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
                    elif dict_ipv4['Protocol'] == 'TCP':
                       for i in range (0, len(gateway[3])):
                          if gateway[3][i] == int(dict_transport['source']):
                             verbose("Allowed incoming,  IPv4/TCP segment from host/GW towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                             return True
                       reason = "non-allowed IPv4/TCP segment sent from host/gw towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
                    else:
                       reason = "received IPv4 packet from host/GW of non-allowed transport protocol ["+dict_ipv4['Protocol']+"] for "+dict_eth['destination']+'/'+dict_ipv4['destination']              
                       
              elif known_external_source_mac:
                 if known_external_source_ip:                           
                    # Incoming traffic from a known external host <- towards -> a known internal host 
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
              else:
                 reason = 'Outer non allowed host ['+dict_eth['source']+'] attempted to send to inner host ['+dict_eth['destination']+']'
                         
           else:
              reason = 'outer host '+dict_eth['source']+'/'+dict_ipv4['source']+' attempted to send to a non verified internal host mac in a non verified ip address '+dict_eth['destination']+'/'+dict_ipv4['destination']
        elif broadcast_dest_mac:
           reason = 'broadcast is not allowed from external hosts, received from: '+dict_eth['source']
        else:
           reason = 'outer host '+dict_eth['source']+' attempted to send to non verified internal mac host '+dict_eth['destination']              
           
     # outcoming traffic
     else:    
        if known_internal_source_mac:               
           if known_internal_source_ip:                 
              # now we are sure that the packet leaves from a known inner host
              if gw_dest_mac:           
                 if not gw_dest_ip:                                     
                    #IPv4 WAN outcoming traffic                   
                    if dict_ipv4['Protocol'] == 'UDP':
                       if is_source_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['source']):
                                return True
                          reason = 'WAN outcoming traffic: '+dict_ipv4['Protocol']+': verified server '+dict_ipv4['source']+' attempted to send from a non allowed port '+dict_transport['source']+' towards client wan ip addr '+dict_ipv4['destination']+':'+dict_transport['destination']
                       elif int(dict_transport['source']) >= 1024:
                          return True   
                       else:
                          reason = 'WAN outcoming traffic: '+dict_ipv4['Protocol']+': non-server host '+dict_ipv4['source']+' attempted to send from a not allowed port '+dict_transport['source']+' towards wan ip addr '+dict_ipv4['destination']+':'+dict_transport['destination']
                    elif dict_ipv4['Protocol'] == 'TCP':
                       if is_source_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['source']):
                                return True
                          reason = 'WAN outcoming traffic: '+dict_ipv4['Protocol']+': verified server '+dict_ipv4['source']+' attempted to send from a non allowed port '+dict_transport['source']+' towards client wan ip addr '+dict_ipv4['destination']+':'+dict_transport['destination']
                       elif int(dict_transport['source']) >= 1024:
                          return True   
                       else:
                          reason = 'WAN outcoming traffic: '+dict_ipv4['Protocol']+': non-server host '+dict_ipv4['source']+' attempted to send from a not allowed port '+dict_transport['source']+' towards wan ip addr '+dict_ipv4['destination']+':'+dict_transport['destination']
                    else:
                       reason = 'Non allowed transport protocol detected '+dict_ipv4['Protocol']+" from "+dict_ipv4['source']              

                 else:
                    # Outoming traffic from a known internal host <- towards -> gw as a host
                    if dict_ipv4['Protocol'] == 'ICMP':
                       verbose('Allowed outcoming, IPv4/ICMP from inner host '+dict_eth['source']+'/'+dict_ipv4['source']+' towards GW',1)
                       return True
                    elif dict_ipv4['Protocol'] == 'UDP':
                       for i in range (0, len(gateway[3])):
                          if gateway[3][i] == int(dict_transport['destination']):                       
                             verbose("Allowed, IPv4/UDP datagramm from inner host: "+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+" towards GW in port "+dict_transport['destination'],1)
                             return True
                       reason = 'non allowed, IPv4/UDP datagramm from inner host: '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+" towards GW in port "+dict_transport['destination']
                    elif dict_ipv4['Protocol'] == 'TCP':
                       for i in range (0, len(gateway[3])):
                          if gateway[3][i] == int(dict_transport['destination']):                       
                             verbose("Allowed, IPv4/TCP segment from inner host: "+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+" towards GW in port "+dict_transport['destination'],1)
                             return True
                       reason = 'non allowed, IPv4/TCP segment from inner host: '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+" towards GW in port "+dict_transport['destination']
                    else:
                       reason = "received IPv4 packet from known internal host of non-allowed transport protocol ["+dict_ipv4['Protocol']+"] from "+dict_eth['source']+'/'+dict_ipv4['source']
              
              elif known_external_dest_mac:
                 if known_external_dest_ip:             
                    # Incoming traffic from allowed internal hosts <- towards -> allowed external hosts
                    if dict_ipv4['Protocol'] == 'UDP':
                       if is_source_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['source']):
                                return True
                          reason = 'verified server attempted to send from a non verified port'
                       elif int(dict_transport['source']) >= 1024:
                          return True
                       else:
                          reason = ''
                    elif dict_ipv4['Protocol'] == 'TCP':
                       if is_dest_server:
                          for i in range (0, len(server_allowed_ports)):
                             if server_allowed_ports[i] == int(dict_transport['source']):
                                return True
                          reason = 'verified server attempted to send from a non verified port'
                       elif int(dict_transport['source']) >= 1024:
                          return True
                       else:
                          reason = 'non verified server attempted to send from a non verified port'
                    else:
                       reason = 'not allowed protocol'          
                 else:
                    reason = 'the packet was heading to a known external destination mac with a non verified ip address'                
              else:
                 # if you are connected with GW over ssh this may fill your screen
                 # you may allow a similar filter as the following
                 #if (dict_ipv4['source'] == '192.168.1.X' or dict_ipv4['source'] == '192.168.1.Y') and (dict_ipv4['destination'] == '192.168.1.X' or dict_ipv4['destination'] == '192.168.1.Y'):
                 #   return False      
                 reason = 'the packet was heading to a not known external destination mac nor gateway from: '+dict_eth['source']+'/'+dict_ipv4['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']     
                 
           else:
              reason = 'Known internal host mac attempted to send to external network with a non allowed ip address'+dict_eth['source']+'/'+dict_ipv4['source']
        else:
            reason = 'Not known internal host mac '+dict_eth['source']+' attempted to send to external network.'

     #
     # DHCP
     #
     if dict_ipv4['Protocol'] == 'UDP':
        if incoming:
           if dict_transport['source']=='67' and dict_transport['destination']=='68':
              if gw_source_mac:
                 if known_internal_dest_mac or broadcast_dest_mac:
                    verbose('Allowed incoming, DHCP packet from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                    return True
                 else:
                    reason = 'received DHCP for a non-internal host or broadcast from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
              else:
                 reason = 'received DHCP from a non GW host from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
        else:
           if dict_transport['source']=='68' and dict_transport['destination']=='67':
              if gw_dest_mac or broadcast_dest_mac:
                 if known_internal_source_mac:
                    verbose('Allowed outcoming, DHCP packet from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                    return True
                 else:
                    reason = 'sent DHCP from a non known internal host from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']   
              else:
                 reason = 'sent DHCP towards a now known external host from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']

   #
   # IPv6
   #
   # some routers or gateways need to send/receive IPv6 packets
   # for this reason IPv6 exchange may only be allowed with host/gw for two specific reasons
   # for ICMP and DHCP
   # but may not be allowed for WAN
   #
   elif dict_eth['EtherType'] == 'IPv6':
      if incoming:
         if gw_source_mac:
            if dict_ipv4['source'] == gateway[2]:
               if known_internal_dest_mac:
                  # Incoming, gateway <- towards -> known internal hosts
                  if dict_ipv4['Protocol'] == 'ICMP':
                     verbose('Allowed incoming,  IPv6 ICMP from '+dict_eth['source']+'/'+dict_ipv4['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination'],1)
                     return True
                  elif dict_ipv4['Protocol'] == 'UDP':      
                     for i in range (0, len(gateway[4])):
                        if gateway[4][i] == int(dict_transport['source']):
                           verbose("Allowed incoming,  IPv6/UDP datagramm from host/GW protocol of source "+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                           return True
                     reason = "non-allowed IPv6/UDP datagramm sent from host/gw of source "+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']                                       
                  else:
                     reason = 'IPv6 packet of non-allowed protocol '+dict_transport['Protocol']
               else:
                  reason = 'GW sent to not-known internal mac address '+dict_eth['destination']
            else:
               # no WAN with IPv6
               reason = 'IPv6 packet from WAN with ip source '+dict_ipv4['source'] 
         else:
            reason = 'not-allowed IPv6 exchange with other hosts except GW '+dict_eth['source']+" to "+dict_eth['destination']   

      else:
         if gw_dest_mac:
            if dict_ipv4['destination'] == gateway[2]:
               if known_internal_source_mac:
                  # Outcoming known internal hosts <- towards -> gateway
                  if dict_ipv4['Protocol'] == 'ICMP':
                     verbose('Allowed outcoming, IPv6 ICMP from '+dict_eth['source']+'/'+dict_ipv4['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination'],1)
                     return True
                  elif dict_ipv4['Protocol'] == 'UDP':
                     for i in range (0, len(gateway[4])):
                        if gateway[4][i] == int(dict_transport['destination']):
                           verbose("Allowed outcoming, IPv6/UDP datagramm from host/GW protocol of source "+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                           return True
                     reason = "non-allowed IPv6/UDP datagramm sent from host/gw of source "+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+" towards "+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
                  else:
                     reason = 'IPv6 packet of non-allowed protocol '+dict_transport['Protocol']
               else:
                  reason = 'not allowed internal mac address '+dict_eth['source']+' attempted to sent to GW'
            else:
               # no WAN with IPv6
               reason = 'IPv6 packet was heading to another host ip addr '+dict_ipv4['destination']
         else:
            reason = 'IPv6 packet was heading to '+dict_eth['destination']

      #
      # DHCPv6
      #
      if dict_ipv4['Protocol'] == 'UDP':
         if incoming:
            if dict_transport['source']=='547' and dict_transport['destination']=='546':
               if gw_source_mac:
                  if known_internal_dest_mac or broadcast_dest_mac:
                     verbose('Allowed incoming, DHCPv6 packet from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                     return True
                  else:
                     reason = 'received DHCPv6 for a non-internal host or broadcast from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
               else:
                  reason = 'received DHCPv6 from a non GW host from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
         else:
            if dict_transport['source']=='546' and dict_transport['destination']=='547':
               if gw_dest_mac or broadcast_dest_mac:
                  if known_internal_source_mac:
                     verbose('Allowed outcoming, DHCPv6 packet from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination'],1)
                     return True
                  else:
                     reason = 'sent DHCPv6 from a non known internal host from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
               else:
                  reason = 'sent DHCPv6 towards a now known external host from '+dict_eth['source']+'/'+dict_ipv4['source']+':'+dict_transport['source']+' towards '+dict_eth['destination']+'/'+dict_ipv4['destination']+':'+dict_transport['destination']
       

   #
   # ARP
   #
   # When incoming arp:
   # It may be from gw and from [known external hosts] <- towards -> [known internal hosts and broadcast]
   # 
   # When outcoming arp:
   # It may be from [known internal] <- towards -> [gateway, broadcast, known external]
   # 
   elif dict_eth['EtherType'] == 'ARP':            

      if incoming:
         if gw_source_mac or known_external_source_mac:
            if known_internal_dest_mac or broadcast_dest_mac:
               verbose('Allowed incoming,  ARP from '+dict_eth['source']+' towards '+dict_eth['destination'],1)
               return True
              
      else:
         if known_internal_source_mac:
            if broadcast_dest_mac or gw_dest_mac or known_external_dest_mac:
               verbose('Allowed outcoming, ARP from '+dict_eth['source']+' towards '+dict_eth['destination'],1)               
               return True
      
      reason = 'Could not allow ARP packet from '+dict_eth['source']+' towards '+dict_eth['destination']

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
   elif EtherType == '86dd':
      s_EtherType = 'IPv6'
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
   if protocol == '01':
     s_prot = 'ICMP'
   elif protocol == '06':
     s_prot = 'TCP'
   elif protocol == '11':
     s_prot = 'UDP'
   else:
     s_prot = protocol   
   s_source_ip = str(int(source_ip[0:2],16))+'.'+str(int(source_ip[2:4],16))+'.'+str(int(source_ip[4:6],16))+'.'+str(int(source_ip[6:8],16))
   s_dst_ip = str(int(destination_ip[0:2],16))+'.'+str(int(destination_ip[2:4],16))+'.'+str(int(destination_ip[4:6],16))+'.'+str(int(destination_ip[6:8],16))
   return {'Protocol':s_prot,'source':s_source_ip,'destination':s_dst_ip}

def get_ipv6_dict(hex_str_frame):
   header =  hex_str_frame[28:28+80]
   protocol =  hex_str_frame[28+12:28+12+2]   
   source_ip = hex_str_frame[28+16:28+16+32]
   dest_ip = hex_str_frame[28+16+32:28+16+32+32]
   if protocol == '3a':
     s_prot = 'ICMP'
   elif protocol == '06':
     s_prot = 'TCP'
   elif protocol == '11':
     s_prot = 'UDP'
   else:
     s_prot = protocol
   s_source_ip = ':'.join([source_ip[i:i+4] for i in range(0, len(source_ip), 4)])
   s_dest_ip = ':'.join([dest_ip[i:i+4] for i in range(0, len(dest_ip), 4)])   
   return {'Protocol':s_prot,'source':s_source_ip,'destination':s_dest_ip}

def get_udp_dict(hex_str_frame,version):
   if version == 4:
      offset = 28 + 40
   else:
      offset = 28 + 80
   source = hex_str_frame[offset:offset+4]
   s_source = str(int(source,16))
   destination = hex_str_frame[offset+4:offset+4+4]
   s_destination = str(int(destination,16))
   return {'source':s_source, 'destination':s_destination}

def get_tcp_dict(hex_str_frame,version):
   if version == 4:
      offset = 28 + 40
   else:
      offset = 28 + 80
   source = hex_str_frame[offset:offset+4]
   s_source = str(int(source,16))
   destination = hex_str_frame[offset+4:offset+4+4]
   s_destination = str(int(destination,16))
   return {'source':s_source, 'destination':s_destination}   

# incoming/outcoming traffic   
def from_ethA_to_ethB(s1,s2,incoming):
   print("started "+str(incoming))
   frame_id = 0 
   allowed_frame_id = 0

   while True:
      frame = s1.recvfrom(65565)[0]
      hex_str_frame = binascii.hexlify(frame).decode('ascii')       
      dict_eth = get_ethernet_dict(hex_str_frame)
      dict_ip = {}
      dict_transport = {}
      if dict_eth['EtherType'] == 'IPv4':
         dict_ip = get_ipv4_dict(hex_str_frame)
         if dict_ip['Protocol'] == 'UDP':
            dict_transport = get_udp_dict(hex_str_frame,4)                        
         elif dict_ip['Protocol'] == 'TCP':
            dict_transport = get_tcp_dict(hex_str_frame,4)
      if  dict_eth['EtherType'] == 'IPv6':
         dict_ip = get_ipv6_dict(hex_str_frame)
         if dict_ip['Protocol'] == 'UDP':
            dict_transport = get_udp_dict(hex_str_frame,6)
         elif dict_ip['Protocol'] == 'TCP':
            dict_transport = get_tcp_dict(hex_str_frame,6)
      
      if firewall(frame_id, incoming, hex_str_frame, dict_eth, dict_ip, dict_transport):         
         s2.send(modify(frame))
         monitor(frame_id, allowed_frame_id, incoming,hex_str_frame,dict_eth,dict_ip,dict_transport)
         allowed_frame_id = allowed_frame_id + 1
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
