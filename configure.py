# Your gateway/router should be physically placed in the external network
# Place your Gateway's data here
# use like:
# mac_address, ipv4 address, allowed host ports
# gateway = ('4f:4f:4f:4f:4f:4f','192.168.1.1',[53,80,443])
gateway = ('4f:4f:4f:4f:4f:4f','192.168.1.1',[53,80,443])

# You may include additional external hosts
# use like:
# mac address, ip address, is_server, allowed server ports
# allowed_external_hosts = [
# ('bf:bf:bf:bf:bf:bf','192.168.1.5',False,[]),
# ('af:af:af:af:af:af','192.168.1.12',True,[80,443])
# ]
allowed_external_hosts = [
]

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
('01:01:01:01:01:01','192.168.1.22',False,[]),
('BB:BB:BB:BB:BB:BC','192.168.1.23',True,[80,443]),
]
