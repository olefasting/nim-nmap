import nmap

##Scanning one host with multiple ports
var host = "192.168.0.11"
for i in countup(1, 999):
   portList.add(i)
nmapScan(host, 0)

##Scanning a netmask on port 80
createMask("192.168.1.1/24")
for i in netMask:
   nmapScan(i, 80)

##Host Discovery on port 22(SSH) and HTTP(port 80). i.e. SSH and HTTP are interchangeable
##With their respected ports and vice versa
portList.add(22)
portList.add(HTTP)
nmapHostDisc()

##low-level socket control using nmapScan()
nmapScan("192.168.1.1", 80, IPv4, STREAM, TCP)
