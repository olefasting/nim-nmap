# nim-nmap
A pure implementation of Nmap for Nim
<br>
<br>
Documentation will be added as this project progresses as well as commented sections in the source code
<br>
<br>

# Commands

<br>
* nMap_iface()
 * Non-functional in current state
 * Native implementation without ExecCmd
<br>
* nMap_scan(host: string, Port(port: int)
* nMap_scan(host: string, Port(port: int, aType: Domain, sType: SockType, nType: Protocol)
<br>
<br>

# Arguments

<br>
* Domain
 * IPv4
 * IPv6
* SockType
 * STREAM
 * DGRAM
 * SRAW
 * SEQPACKET
* Protocol
 * TCP
 * UDP
 * RAW
 * ICMP

# Roadmap to v1.0
[x] Basic socket support
<br>
[ ] Read packet information(i.e. TTL, WindowSize)
<br>
[ ] Test if Ports are filtered or not
<br>
[ ] Host Discovery
<br>
[ ] OS Fingerprinting
<br>
[ ] nMap_iface()
