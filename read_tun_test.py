#!/usr/bin/env python3
#!/usr/bin/python3

import fcntl
import os
import struct
import subprocess
import time

from array import array

# Some constants used to ioctl the device file. I got them by a simple C
# program.
TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Open TUN device file.
tun = open('/dev/net/tun', 'r+b', buffering=0)
# Tall it we want a TUN device named tun0.
ifr = struct.pack('16sH', b'tun0', IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)
# Optionally, we want it be accessed by the normal user.
fcntl.ioctl(tun, TUNSETOWNER, 1000)

# Bring it up and assign addresses.
subprocess.check_call('ifconfig tun0 192.168.7.1 pointopoint 192.168.7.2 up',
        shell=True)

while True:
    # Read an IP packet been sent to this TUN device.
    packet = array('B', os.read(tun.fileno(), 2048))
    print(packet)
    print(" ".join([str(hex(i)).replace("0x", "") for i in packet]))

