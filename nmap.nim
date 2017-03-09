##
## A native nmap implementation for nim
## https://github.com/blmvxer/nim-nmap
##
## Credit: https://nmap.org
##
## Released under GPLv2, see LICENSE file
## 2017 - blmvxer <blmvxer@gmail.com>
##

{.deadCodeElim: on.}

import net, strutils, os

type
   host = string
   port = int

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

################################################################

proc nmap_iface*(): int {.exportc.} = ##Display current network interfaces
   let iFace = execShellCmd("ifconfig")
   return (iFace)

proc nmap_scan*(host: string, port: int): string {.discardable.} = ##basic nmap and port scan
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
