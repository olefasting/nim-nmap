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

import strutils, httpclient

type
   host = string
   lHost = bool
   lPort = bool
   rHost = bool
   rPort = bool

var
   portNum = [20, 21, 22, 23, 80, 443]##Common ports
   portDes = ["ftp", "sftp", "ssh", "telnet", "http", "https"]

proc nmap_scan*(host, port: string): Response {.exportc.} = ##basic nmap and port scan
   try:
      var
         timeout = 5
         client = newHttpClient(timeout = timeout * 1000)
         url = "http://" & host & ":" & port
         resp = client.request(url)
      echo resp.status
   except:
      let testPort: string = getCurrentExceptionMsg()
      let portResp = find(testPort, "SSH")
      if portResp != -1:
         echo split(testPort, "invalid http version, ")
      else:
         echo "SSH port not open or filtered"
