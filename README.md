Portscanner in C++

This port scanner can peforme multiple types of scan including: 
TCP connect, UDP/ICMP, SYN|ACK, XMAS, NULL, FIN and SYN.
The TCP connect scan is simple but easily detectable. It initiates
a three way handshake by connecting to the specified pair of host:port.
If connection is successful the port is open. The other methods are more tedious
and require the use of raw sockets and sending of custom made packet headers with 
the appropriate flags set. All scans can be peformed over a range of hosts/IPs
simultaneously using threads. When doing a range scan, to avoid being detected,
each IP is only scanned once every 0.5 + random interval seconds.

Note: The stealth scans XMAS, NULL, FIN and SYN|ACK, produce alot of false positives
on most host setups.
	
Links to influential sources that inpired ideas:
http://tuprints.ulb.tu-darmstadt.de/6243/1/TR-18.pdf
http://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libfree/in_cksum.c 
https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
http://www.matveev.se/cpp/portscaner.htm

To compile: make
To run: sudo ./portscanner -flag

flag options:
-s: syn scan (default)
-t: tcp scan
-u: udp scan
-f: fin scan
-y: syn ack scan
-x: xmas scan
-n: null scan

Example output:
sudo ./portscanner -t
Starting TCP scan...
Scan report for scanme.nmap.org
Closed ports(not shown): 20
31337 is open
554 is open
9929 is open
7070 is open

sudo ./portscanner -s
Starting SYN scan...
Scan report for scanme.nmap.org
Closed ports(not shown): 20
9929 is open
554 is open
31337 is open
7070 is open

sudo ./portscanner -u
Starting UDP scan...
Scan report for scanme.nmap.org
Closed ports(not shown): 22
123 is open
68 is open
