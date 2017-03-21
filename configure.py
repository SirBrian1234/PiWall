#
# PiWall
#
# please use eth0 to access piwall as a host
# eth1 to connect piwall towards the external network
# eth2 to connect piwall towards the internal network
# (physically) set eth0 to he a host in the internal network
# in order to avoid u-turns or unnecessairy traffic please provide
# piwall's eth1 and eth2 mac addresses here
piwall_eth1_mac = 'bb:bb:bb:bb:bb:bb'
piwall_eth2_mac = 'cc:cc:cc:cc:cc:cc' 


#
# Gateway / Router
#
# Your gateway/router should be physically placed in the external network
# Place your Gateway's data here
# use like:
# mac_address, ipv4 address, ipv6 address, allowed host ports
# gateway = ('4f:4f:4f:4f:4f:4f','192.168.1.1','0000:0000:0000:0000:0000:0000:0000:0000',[53,80,443],[53])
# some routers GWs may require ipv6 to be used for dhcp, icmp, dns if that's the case include your GW's ipv6 address on a long form
gateway = ('4f:4f:4f:4f:4f:4f','192.168.1.1','0000:0000:0000:0000:0000:0000:0000:0000',[53,80,443],[53])

#
# External hosts
#
# You may include additional external hosts
# use like:
# mac address, ip address, is_server, allowed server ports
# allowed_external_hosts = [
# ('ba:ba:ba:ba:ba:ba','192.168.1.7',False,[]),
# ('a3:a3:a3:a3:a3:a3','192.168.1.3',True,[80,443])
# ]
allowed_external_hosts = [
('ba:ba:ba:ba:ba:ba','192.168.1.7',False,[]),
('a3:a3:a3:a3:a3:a3','192.168.1.3',True,[80,443])
]

#
# Internal hosts
#
# Here internal hosts may be defined in similar format
# only defined internal host may be connected to WAN
# only defined servers with ports may be found
# use like:
# mac address, ip address, is_server, allowed server ports
# allowed_internal_hosts = [
# ('bf:bf:bf:bf:bf:bf','192.168.1.5',False,[]),
# ('af:af:af:af:af:af','192.168.1.12',True,[80,443])
# ]
allowed_internal_hosts = [
('bf:bf:bf:bf:bf:bf','192.168.1.5',False,[]),
('af:af:af:af:af:af','192.168.1.12',True,[80,443])
]
