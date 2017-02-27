##
## A wrapper for nmap on nim
## https://github.com/blmvxer/nim-nmap
##
## Wraps nmap https://nmap.org
##
## Released under GPLv2, see LICENSE file
## 2017 - blmvxer <blmvxer@gmail.com>
##


import strutils

{.deadCodeElim: on.}

const nmap_scan = "/usr/bin/nmap"

type PortScanner* = ref object of RootObj
