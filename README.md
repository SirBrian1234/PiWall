# Under Dev

# PyWall
Set your firewall the pythonic way! The PyWall project is a secure and standalone low-level (Layer 2 OSI) network firewall with enchanced flexibility as its rules and policies may directly be defined in Python (3.4).

## Learn - Project
PyWall can:
* Monitor your traffic on the fly
* Firewall your traffic on the fly
* Modify your traffic on the fly
* Provide live information for all the above

**PyWall was implemented and tested as PiWall! A Raspberry Pi model B based system running Raspbian Linux!**
In order to learn more about the project's idea, the implemented project in its overall, how PiWall works, as well as how to build and set up your own device, please visit the PiWall project page from here:

[..the project's page is currently under dev..]

The PyWall project may be implemented in other Unix/Linux systems as long as the target system has three or more network interface cards and is able to install and run the following packages.
On Debian based systems such as Raspbian you may setup your device as described below:

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
* pywall.py: lets you define pywall's behaviour
* pywall-learn.py: lets you start a simple bridge connection in order to understand how pywall works

## Edit 
Edit configure.py in order to set your personalised network settings.
```
cd PyWall
nano configure.py
nano pywall.py
```

## Run
```
cd PyWall
sudo python3 pywall.py
```
Repeat the edit and run steps until PyWall is configured according to your network needs.

## Register PiWall on system's start
In order to register the PiWall service on system's start you should set an init script as defined below. You should set your two interfaces in promiscious mode in order to let pywall be able to read and write frames in them.
```
sudo nano /etc/init.d/init_pywall
```

```
#!/bin/bash

### BEGIN INIT INFO
# Provides: init_pywall
# Required-Start: $all
# Required-Stop:
# Default-Start: 4
# Default-Stop:
# Short-Description: This script intialises the pywall service.
# Description: This script inits pywall service.
### END INIT INFO

(
ifconfig eth0 down
ifconfig eth1 up
ifconfig eth1 promisc
ifconfig eth2 up
ifconfig eth2 promisc
sleep 5
sudo python3 /home/pi/PyWall/pywall.py &
sleep 10
ifconfig eth0 up
) > /home/pi/init_pywall.log
```

```
sudo chmod +x /etc/init.d/init_pywall
sudo update-rc.d init_pywall defaults
```

## Debugging
You should make sure that the eth1 interface is connected with the gateway and eth2 are the internal hosts. In order to check that do:
```
ifconfig
```
And view if eth1 got the ip address, if not, swap the ethernet cables but do not plug out the usb adapters.

To check the registered service's state you may do:
```
cat /home/pi/init_pywall.log | less
```

To kill the service and start a new one from the terminal:
```
sudo killall python3
cd /home/pi/PyWall
sudo python3 pywall.py
```
When everything is ok you may restart the system.
  
## What's already there
PyWall, as it is right now, has the following logic:

Data:
* Lets you use a frame's EtherType, source and destination mac address.
* Knows when a mac address is broadcast, zero, gateway, internal or external host.
* Lets you use IPv4 source and destination address as well as transmition protocol type
* Knows when an ip address is broadcast zero or host-reserved
* Lets you use source port and destination port of TCP, UDP protocols

Functional:
* PyWall has external host mac whitelist and internal host mac whitelist to filter trafic
* Known internal Mac-to-Ip table to prevent IP address spoofing
* Only GateWay may serve packets from multiple ip adresses.
* Let's you define whether a host may be treated as a server and which ports are allowed
* Defined policies about ARP, IPv4 and DHCP protocol behaviours
* Multi-scale verbose level to let you define the amount of information you would like to receive

## License
The project's article and source code are licensed under Creative Commons Atribution 4.0 International: https://creativecommons.org/licenses/by/4.0/

You may use the source code commercially.
You should provide attribution for all the authors involved in this project.
