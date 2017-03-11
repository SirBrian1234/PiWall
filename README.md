# Under Dev

# PiWall
The PiWall project is a secure low-level network firewall with enchanced flexibility as its policies and rules may directly be defined in Python.

## Learn
PiWall can:
* Monitor your traffic
* Firewall your traffic
* Modify your traffic on the fly

In order to learn more about PiWall, how PiWall works and how to build and set up your own device, please view PiWall's project page from here:
[...]

## Install Source Code
In order to install the project's source code from your raspberry pi/raspbian run the following commands:

```
sudo apt-get update
sudo apt-get install git python3 python3-pip
git clone https://github.com/kostiskag/PiWall.git
cd PiWall
```

## Learn - Source code
In the repository you may find four python files:
* network_rules.py: lets you define your network rules
* firewall.py: lets you define your firewall's monitor policy and modify behaviour
* init_firewall.py: lets you start a bridge connection with firewall
* d_init_firewall.py start|stop|restart: lets you start the firewall bridge as a daemon service

## register firewall-bridge on system's start
In order to register the firewall service on system's start you should set an init script as defined below:
```
sudo nano /etc/init.d/init_firewall
```

```
#!/bin/bash

### BEGIN INIT INFO
# Provides: init_gps
# Required-Start: $all
# Required-Stop:
# Default-Start: 4
# Default-Stop:
# Short-Description: Initialises the bridge and firewall service.
# Description: Inits the br and fw service.
### END INIT INFO
python3 d_init_firewall.py start
```

```
sudo chmod +x /etc/init.d/init_firewall
```

## License
The project's article and source are licensed under Creative Commons Atribution 4.0 International: https://creativecommons.org/licenses/by/4.0/

You may use the source code commercially. You should provide attribution for all the authors involved in the project.
