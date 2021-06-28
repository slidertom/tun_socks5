# tun_socks5

### Intro
tunproxy forwards all ipv4 udp traffic   
into socks5 server using locally created tun interface.

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

## Tun
Tun interface tutorial/intro https://backreference.org/2010/03/26/tuntap-interface-tutorial/  
Reused https://github.com/LaKabane/libtuntap   

## Multiplex
Epoll is used for polling. Could be also Poll.   
https://www.ulduzsoft.com/2014/01/select-poll-epoll-practical-difference-for-system-architects/
