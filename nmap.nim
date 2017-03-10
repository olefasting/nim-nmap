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

##Constant Values, Types and Exports
const
   TCP = IPPROTO_TCP
   UDP = IPPROTO_UDP
   RAW = IPPROTO_RAW
   ICMP = IPPROTO_ICMP
   IPv4 = AF_INET
   IPv6 = AF_INET6
   STREAM = SOCK_STREAM
   DGRAM = SOCK_DGRAM
   SRAW = SOCK_RAW
   SEQPACKET = SOCK_SEQPACKET
   SSH = 22
   TELNET = 23
   HTTP = 80
   HTTPS = 443

var
   aType = IPv4   #Domain
   sType = STREAM #sockType
   nType = TCP    #Protocol
   recPacket = newString(1024)

export SSH, TELNET, HTTP, HTTPS, TCP, UDP, RAW, ICMP
export IPv4, IPv6, STREAM, DGRAM, SRAW, SEQPACKET
export aType, sType, nType

################################################################
type portArray = array[0..3, int]
var portList: portArray
portList = [22, 23, 80, 443]
var portLen = portList.len

################################################################

proc nMap_iface*(): (string, Port) {.discardable.} =
   var self = newSocket(IPv4, STREAM, TCP)
   self.bindAddr(Port(83))
   self.listen()
   let iface = getPeerAddr(self)
   echo iface


#This proc is standard connect
proc nMap_scan*(host: string, port: int): string {.discardable.} =
   try:
      var sock = newSocket(IPv4, STREAM, TCP)
      sock.connect(host, Port(port))
      let sPort = intToStr(port)
      echo host & " Connected succesfully on " & sPort
      sock.close()
   except:
      let ErrorMsg = getCurrentExceptionMsg()
      let sPort = intToStr(port)
      echo ErrorMsg &  " on " & sPort

#This proc allows additional low-level control
proc nMap_scan*(host: string, port: int,
                aType: Domain, sType: SockType, nType: Protocol):
                string {.discardable.} =
   try:
      if nType == UDP:
         var sock = newSocket()
         discard sock.sendTo(host, Port(port), "status\n")
         let recPacket = sock.recvLine(1024 * 5)
         echo sizeOf(recPacket)
      else:
         var sock = newSocket(aType, sType, nType)
         sock.connect(host, Port(port))
         let sPort = intToStr(port)
         echo host & " Connected succesfully on " & sPort
         sock.send("bbHHh")
         let recPacket = sock.recvLine(1024 * 5)
         echo sizeOf(recPacket)
         sock.close()
   except:
     let ErrorMsg = getCurrentExceptionMsg()
     let sPort = intToStr(port)
     echo ErrorMsg &  " on " & sPort
