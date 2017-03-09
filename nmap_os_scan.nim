import net, nmap

const 
   TCP = IPPROTO_TCP
   UDP = IPPROTO_UDP
   RAW = IPPROTO_RAW
   ICMP = IPPROTO_ICMP
   IPv4 = AF_INET
   IPv6 = AF_INET6
   STREAM = SOCK_STREAM
   DGRAM = SOCK_DGRAM
   sRAW = SOCK_RAW
   SEQPACKET = SOCK_SEQPACKET
   SSH = 22
   TELNET = 23
   HTTP = 80
   HTTPS = 443

proc osscan(host: string, port: int) = 
   try:
      var sock = newSocket(IPV4, STREAM, TCP)
      sock.connect(host, Port(port))
   except:
      let ErrorMsg = getCurrentExceptionMsg()
      echo ErrorMsg

osscan("192.168.0.11", 24)
