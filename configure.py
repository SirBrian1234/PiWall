# Place your Gateway here or other hosts outside that you would like 
# to be reached
allowed_external_host_macs = [
'ff:ff:ff:ff:ff:ff',
'4d:4d:4d:4d:4d:4d' #GW
]

#Place the host macs behind the firewall here
allowed_host_macs = [
'bf:bf:bf:bf:bf:bf', 
'ba:ba:ba:ba:ba:ba'  
]

# add a mac to ip mapping in order to defend against ip spoofings
# place in true false whether a host may be a server
# mac, ip_addr, is_server
known_ips_to_mac = [
('bf:bf:bf:bf:bf:bf','192.168.2.15',False),
('ba:ba:ba:ba:ba:ba','192.168.2.22',True)
]
