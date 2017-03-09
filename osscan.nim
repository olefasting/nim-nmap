import net, strutils, nmap

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

type portArray = array[0..3, int]
var portList: portArray
portList = [22, 23, 80, 443]
var portLen = portList.len

proc osscan(host: string, port: int) = 
   try:
      var sock = newSocket(IPV4, STREAM, TCP)
      sock.connect(host, Port(port))
      let sPort = intToStr(port)
      echo host & " Connected succesfully on " & sPort
      sock.close()
   except:
      let ErrorMsg = getCurrentExceptionMsg()
      let sPort = intToStr(port)
      echo ErrorMsg &  " on " & sPort
var i = 0
while i != portLen:
   osscan("192.168.0.11", portList[i])
   i = i + 1
