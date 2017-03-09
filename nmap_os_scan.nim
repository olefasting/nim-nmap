import nativesockets
from posix import fork

const sockBuff = 65596

var
   data = newString(sockBuff)
   pData: pointer = data.addr
   addrHost = cast[ptr uint32](cast[int]("192.168.1.110".cstring))[]
   port = 80
   sock = newNativeSocket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
sock.setSockOptInt(cint(SOL_SOCKET), SO_REUSEADDR, 1)
sock.setBlocking(false)
discard fork()

var name: SockAddr_in
name.sin_family = toInt(AF_INET)
name.sin_port = htons(80'u16)
name.sin_addr.s_addr = addrHost

discard sock.bindAddr(cast[ptr SockAddr](addr name), Socklen(sizeof(name)))
discard sock.listen()

var
   sockAddress: Sockaddr_in
   addrLen = Socklen(sizeof(sockAddress))
   osDet = sock.bindAddr(cast[ptr SockAddr](addr(sockAddress)), addrLen)

let response = sock.recvfrom(pData, sockBuff, O_NONBLOCK, cast[ptr SockAddr](addr(sockAddress)), addr(addrLen))
echo response
sock.close()
