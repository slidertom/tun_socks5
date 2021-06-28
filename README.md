# tun_socks5

### Intro
tunproxy acts as udp traffic proxy.
Forwards all udp traffic into socks5 server.

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

### Multiplex
Epoll is used for polling. Could be also Poll. 

https://www.ulduzsoft.com/2014/01/select-poll-epoll-practical-difference-for-system-architects/
