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
   sRAW = SOCK_RAW
   SEQPACKET = SOCK_SEQPACKET
   SSH = 22
   TELNET = 23
   HTTP = 80
   HTTPS = 443
#   defineNet = defined(c_net)

var
   aType = IPv4   
   sType = STREAM
   nType = TCP

   
#when defineNet: TODO:Add lowlevel control
#   case cNet: bool
#   of true:
#      type
#         customNet* = enum
#         aType = Domain, sType = SockType, nType = Protocol
   
export SSH, TELNET, HTTP, HTTPS, TCP, UDP, RAW, ICMP
export IPv4, IPv6, STREAM, DGRAM, sRAW, SEQPACKET
export aType, sType, nType

################################################################
type portArray = array[0..3, int]
var portList: portArray
portList = [22, 23, 80, 443]
var portLen = portList.len

################################################################

proc nmap_iface*(): int {.exportc.} = ##Display current network interfaces
   let iFace = execShellCmd("ifconfig")
   return (iFace)
##Begin nmap_scan
proc nmap_scan*(host: string, port: int): string {.discardable.} =
   try:
      var sock = newSocket(aType, sType, nType)
      sock.connect(host, Port(port))
      let sPort = intToStr(port)
      echo host & " Connected succesfully on " & sPort
      sock.close()
   except:
     let ErrorMsg = getCurrentExceptionMsg()
     let sPort = intToStr(port)
     echo ErrorMsg &  " on " & sPort
