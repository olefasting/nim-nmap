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

type host = string

proc nmap_scan*(host, port: string): Response {.exportc.} =
   var
      timeout = 5
      client = newHttpClient(timeout = timeout * 1000)
      url = "http://" & host & ":" & port
      resp = client.request(url)
   echo resp.status

