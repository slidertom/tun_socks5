# tun_socks5

### Intro
tunproxy forwards all ipv4 udp traffic   
into socks5 server using locally created tun interface.

NO AUTHENTICATION is supported only.

### Dependencies

cmake or codeblocks  
iproute2  
build-essential  

### Compilation

```sh
mkdir build
cd build
cmake ..
make
```

### Documentation 

#### Tun
Tun interface tutorial/intro https://backreference.org/2010/03/26/tuntap-interface-tutorial/  
Reused https://github.com/LaKabane/libtuntap   

#### Multiplex
Epoll is used for polling. Could be also Poll.   
https://www.ulduzsoft.com/2014/01/select-poll-epoll-practical-difference-for-system-architects/

io_uring would be nice to review: (required kernel version 5.1)
https://blogs.oracle.com/linux/post/an-introduction-to-the-io_uring-asynchronous-io-framework  
open discussion: io_uring is slower than epoll
https://github.com/axboe/liburing/issues/189

### Protocols
udp ipv4 is only supported.
udp packet construction is low level for the learning purposes.   
boost asio must be used or similar library.  

### Test
Utility tested with glider: https://github.com/nadoo/glider  
  
Download: https://github.com/nadoo/glider/releases  
or direct link  
https://github.com/nadoo/glider/releases/download/v0.14.0/glider_0.14.0_linux_amd64.tar.gz  
  
```sh
glider -verbose -listen socks5://:1080
````
  
Utility does not work with dante.  
https://www.inet.no/dante/  
Probably dante expects client side port   
during UDP ASSOCIATE request.  

udp packets emulation  
simply: dig domain (e.g.: dig www.google.com)  
iperf3 (debian: https://packages.debian.org/search?keywords=iperf3)  
server: iperf3 -s  
client: iperf3 -u -c client.ip.address -b 1M  


