##
## A native nmap implementation for nim
## https://github.com/blmvxer/nim-nmap
##
## Credit: https://nmap.org
##
## Released under GPLv2, see LICENSE file
## 2017 - blmvxer <blmvxer@gmail.com>
##

#Compiler options
{.deadCodeElim: on, hints: off, warnings: off.}
#

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
   aType = IPv4                     #Domain
   sType = STREAM                   #sockType
   nType = TCP                      #Protocol
   recPacket = newString(1024)      #1024bit Packet
   portList: seq[int]               #Custom Ports
#PortList Defaults
portList = @[]
portList.add(22)
portList.add(23)
portList.add(80)
portList.add(443)
##########################################################
export SSH, TELNET, HTTP, HTTPS, TCP, UDP, RAW, ICMP
export IPv4, IPv6, STREAM, DGRAM, SRAW, SEQPACKET
export aType, sType, nType, portList
##########################################################
#nmap commands and additional features
{.experimental.}
proc nMap_iface*(): (string, Port) {.discardable.} =
   var self = newSocket(IPv4, STREAM, TCP)
   self.bindAddr(Port(83))
   self.listen()
   let iface = getPeerAddr(self)
   echo iface
#WIP for pulling interface information from the localhost
#
#Our earlier version included calling ifconfig from -
#the shell rather than using a pure nim solution
#
#hopefully this can be figured out soon...
#


#This proc is standard connect
proc nMap_scan*(host: string, port: int): string {.discardable.} =
   if port == 0:
      for i in portList:
         try:
            var sock = newSocket(IPv4, STREAM, TCP)
            sock.connect(host, Port(i))
            let sPort = intToStr(i)
            echo host & " Connected succesfully on " & sPort
            sock.close()
         except:
            let ErrorMsg = getCurrentExceptionMsg()
            let sPort = intToStr(i)
            echo ErrorMsg &  " on " & sPort
   else:
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
         let recPacket = sock.recvLine(1024 * 5)#TODO Work on sending and receiving data from Packets
         echo sizeOf(recPacket)#TODO
      else:
         var sock = newSocket(aType, sType, nType)#Allow control over Domain, SockType, and Protocol
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
