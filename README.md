# Under Dev

# PiWall
The PiWall project is a Raspberry Pi based, secure and standalone low-level (Layer 2 OSI) network firewall with enchanced flexibility as its rules and policies may directly be defined in Python (3.4).

## Learn - Project
PiWall can:
* Monitor your traffic on the fly
* Firewall your traffic on the fly
* Modify your traffic on the fly
* Provide live information for all the above

In order to learn more about PiWall, how PiWall works, how to build and set up your own device, please visit PiWall's project page from here:
[..the project's page is currently under dev..]

## Install Source Code
In order to install the project's source code from your raspberry pi/raspbian run the following commands:
```
sudo apt-get update
sudo apt-get install git python3 python3-pip
git clone https://github.com/kostiskag/PiWall.git
```

## Learn - Source code
In the repository you may find four python files:
* configure.py: lets you define your network data
* piwall.py: lets you define piwall's behaviour
* piwall-learn.py: lets you start a simple bridge connection in order to understand how piwall works

## Edit 
Edit configure.py in order to set your personalised network settings.
```
cd PiWall
nano configure.py
nano piwall.py
```

## Run
```
cd PiWall
sudo python3 pywall.py
```
Repeat the edit and run steps until PiWall is configured according to your network needs.

## Register PiWall on system's start
In order to register the PiWall service on system's start you should set an init script as defined below. You should have your two interfaces in promiscious mode in order to let piwall to be able to read and write frames in the interface.
```
sudo nano /etc/init.d/init_piwall
```

```
#!/bin/bash

### BEGIN INIT INFO
# Provides: init_piwall
# Required-Start: $all
# Required-Stop:
# Default-Start: 4
# Default-Stop:
# Short-Description: This script intialises piwall.
# Description: This script inits piwall.
### END INIT INFO

(
ifconfig eth0 down
ifconfig eth1 up
ifconfig eth1 promisc
ifconfig eth2 up
ifconfig eth2 promisc
sleep 5
sudo python3 /home/pi/PiWall/piwall.py &
sleep 10
ifconfig eth0 up
) > /home/pi/init_piwall.log
```

```
sudo chmod +x /etc/init.d/init_piwall
sudo update-rc.d init_piwall defaults
```

## Debugging
You should make sure that the eth1 interface is connected with the gateway and eth2 are the internal hosts. In order to check that do:
```
ifconfig
```
And view if eth1 got the ip address, if not, swap the ethernet cables but do not plug out the usb adapters.

To check the registered service's state you may do:
```
cat /home/pi/init_piwall.log | less
```

To kill the service and start a new one from the terminal:
```
sudo killall python3
cd /home/pi/PiWall
sudo python3 piwall.py
```
When everything is ok you may restart the system.
  
## What's already there
PiWall, as it is right now, has the following logic:

Data:
* Lets you use a frame's EtherType, source and destination mac address.
* Knows when a mac address is broadcast, zero, gateway, internal or external host.
* Lets you use IPv4 source and destination address as well as transmition protocol type
* Knows when an ip address is broadcast zero or host-reserved
* Lets you use source port and destination port of TCP, UDP protocols over IPv4 or IPv6
* Lets you use IPv6 source destination address and transmition protocol

Functional:
* PiWall has external host mac whitelist and internal host mac whitelist to filter trafic
* Known internal and external Mac-to-Ip table to prevent IP address spoofing
* Only gateway may serve packets from multiple ip adresses.
* Gateway may be treated as a host and allow/block services like HTTP, DNS
* Let's you define whether an internal or external network  host may be treated as a server and which ports may be allowed
* Defined policies about ARP, IPv4: ICMP, DHCP, IPv6: ICMP, DHCP
* Multi-scale verbose level to let you define the amount of information you would like to receive

## License
The project's article and source are licensed under Creative Commons Atribution 4.0 International: https://creativecommons.org/licenses/by/4.0/

You may use the source code commercially.
You should provide attribution for all the authors involved in this project.
