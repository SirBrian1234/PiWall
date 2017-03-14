# Under Dev

# PiWall
The PiWall project is a secure and standalone low-level network firewall with enchanced flexibility as its policies and rules may directly be defined in Python.

## Learn - Project
PiWall can:
* Monitor your traffic
* Firewall your traffic
* Modify your traffic on the fly

In order to learn more about PiWall, how PiWall works and how to build and set up your own device, please visit PiWall's project page from here:
[...]

## Install Source Code
In order to install the project's source code from your raspberry pi/raspbian run the following commands:

```
sudo apt-get update
sudo apt-get install git python3 python3-pip
git clone https://github.com/kostiskag/PiWall.git
```

## Learn - Source code
In the repository you may find four python files:
* configure.py: lets you define your network rules
* piwall.py: lets you define your firewall's monitor policy and modify behaviour
* piwall-learn.py: lets you start a simple bridge connection in order to understand how piwall works

## Edit 
Edit configure.py in order to set your personalised network
```
cd PiWall
nano configure.py
nano firewall.py
```

## Run
```
cd PiWall
sudo python3 pywall.py
```

## Register PiWall on system's start
In order to register the PiWall service on system's start you should set an init script as defined below. You should have your two interfaces in promiscious mode in order to let piwall to be able to read and write frames in the interface.
```
sudo nano /etc/init.d/init_piwall
```

```
#!/bin/bash

### BEGIN INIT INFO
# Provides: init_gps
# Required-Start: $all
# Required-Stop:
# Default-Start: 4
# Default-Stop:
# Short-Description: inits piwall
# Description: inits piwall
### END INIT INFO

(
ifconfig eth1 up
ifconfig eth1 promisc
ifconfig eth2 up
ifconfig eth2 promisc
sleep 5
sudo python3 /home/pi/PiWall/piwall.py &
) > /home/pi/init_piwall.log
```

```
sudo chmod +x /etc/init.d/init_piwall
sudo update-rc.d init_piwall defaults
```
## What's alleready there
PiWall as it is right now may let you use the following attributes:
let you use a frame's type, source and destination mac addresses.
let you use IPv4 source, destination and protocol
let you use source port and destination port of TCP, UDP protocols

Functional:
PiWall has external host mac whitelist and internal host mac whitelist
Mac to Ip table to prevent IP address spoofing
Let's you define whether a host may be treated as client or as a server
Defined policies about ARP DHCP and IPv4 protocol behaviours

## License
The project's article and source are licensed under Creative Commons Atribution 4.0 International: https://creativecommons.org/licenses/by/4.0/

You may use the source code commercially. You should provide attribution for all the authors involved in the project.
