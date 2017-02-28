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

import strutils, httpclient, os, sequtils

type
   host = string
   port = string
   lHost = bool
   lPort = bool
   rHost = bool
   rPort = bool
   portDes = enum
      ftp, sftp, ssh, telnet, http, https

var
   portArg = ("common")
   portNum: array[6, string]
portNum = ["20", "21", "22", "23", "80", "443"]#Common ports

################################################################

proc nmap_iface*(): int {.exportc.} = ##Display current network interfaces
   let iFace = execShellCmd("ifconfig")
   return (iFace)

proc nmap_scan*(host, port: string): Response {.exportc.} = ##basic nmap and port scan
   try:
      var timeout = 5
      var client = newHttpClient(timeout = timeout * 1000)
      if port == portArg:
         for i in low[portNum]..high[portNum]:
            var url = "http://" & host & ":" & portNum[i]
            var resp = client.request(url)
            echo resp.status
      else:
         var url = "http://" & host & ":" & port
         var resp = client.request(url)
         echo resp.status
   except:
      let testPort: string = getCurrentExceptionMsg()
      let portResp = find(testPort, "SSH")
      if portResp != -1:
         echo split(testPort, "invalid http version, ")
      else:
         echo "SSH port not open or filtered"
