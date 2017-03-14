import nmap, strutils
#var host = "192.168.0.11"
#for i in countup(1, 999):
#   portList.add(i)
#createMask("192.168.1.1/24")
#for i in netMask:
#   nmapScan(i, 80)


let myBool = false

var x = 0
for i in winSpecPort:
   let myBool = contains(i, "139")
   echo myBool
   echo winSpecPort[x]
   inc(x)

nmapHostDisc()
for v in hostDisc:
   for p in winSpecPort:
      nmapScan(v, p)
