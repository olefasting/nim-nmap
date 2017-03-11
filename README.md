# nim-nmap v0.1.4
A pure implementation of Nmap for Nim
<br>
<br>
Documentation will be added as this project progresses as well as commented sections in the source code
<br>
<br>

# Commands

<br>
* nmapIface()
 * Non-functional in current state
 * Native implementation without ExecCmd
<br>
* nmapScan(host: string, Port(port: int)
* nmapScan(host: string, Port(port: int, aType: Domain, sType: SockType, nType: Protocol)
<br>
* nmapHostDisc()
 * Determines local router and host on network
<br>
* portList.add(port: int)
<br>

# Arguments

<br>
* Host
 * IP Address
* Port
 * 0 - Custom ports using portList
 * SSH - 22
 * TELNET 23
 * HTTP - 80
 * HTTPS - 443
 * int - any integer
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
[x] Basic Port Scanner
<br>
[ ] Read packet information(i.e. TTL, WindowSize)
<br>
[ ] Test if Ports are filtered or not
<br>
[x] Host Discovery
<br>
[ ] OS Fingerprinting
<br>
[ ] nmapIface()
<br>
[x] NetMask support for host: string
<br>
<br>
# Examples
## NetMask via createMask() ##

    import nmap
    createMask("192.168.1.1/24") 
    for i in netMask:
      nmapScan(i, 80)

<br>
Result will be something like this.
<br>

    192.168.1.1 Connected succesfully on 80
    192.168.1.2 No route to host on 80
    192.168.1.3 No route to host on 80
<br>
## nmapHostDisc() ##
    import nmap
    for p in countup(1, 999):
       portList.add(p)
    nmapHostDisc()
    
    or
   
    import nmap
    portList.add(22)
    nmapHostDisc()
<br>
Bugs in portList with Host Discovery
<br>
Adding too many ports(700+) results in too many files open
