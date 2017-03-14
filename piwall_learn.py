"""
piwall-learn.py: Here is the core logic of PiWall in order to easily understand 
the logic behind piwall and how the traffic forwarding mechanism is achieved.
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
 
def from_eth1_to_eth2(s1,s2):
   print("started 1")
   while True:
      #print("waiting for packet")
      frame = s1.recvfrom(65565)[0]
      #print(type(frame))
      #print(frame)
      s2.send(frame)
      #print("send to eth2")

def from_eth2_to_eth1(s1,s2):
   print("started 2")
   while True:
      frame = s2.recvfrom(65565)[0]
      s1.send(frame)
      #print("send to eth1")

try:
   s1 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   s2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   s1.bind(("eth1", 0))
   s2.bind(("eth2", 0))   
   _thread.start_new_thread( from_eth1_to_eth2, (s1,s2, ))
   from_eth2_to_eth1(s1,s2)
except:
   print ("Error: unable to start thread")
   print (sys.exc_info()[0])
