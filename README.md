# Dependencies
* Packages (package names listed are for Fedora)
  - libnetfilter_queue-devel
  - python-devel
* Python 2 modules
  - netfilterqueue
  - scapy

# Running the Program
Install the dependencies listed above, then run the program using:

```
python main.py -i router IP -t victim IP -d spoofed domain
```

For instance, to direct traffic from 192.168.1.2 bound for www.cnn.com to your machine where the router (default gateway) is 192.168.1.1:

```
python main.py -i 192.168.1.1 -t 192.168.1.2 -d www.cnn.com
```

This will
1. Poison the 192.168.1.1's and 192.168.1.2's ARP caches
2. Listen for DNS queries for www.cnn.com and respond with the current machine's IP address

To respond with a fake website (using e.g. index.html included with this project), start an HTTP server before starting the DNS spoofer.
