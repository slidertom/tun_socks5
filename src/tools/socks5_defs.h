#pragma once

// follow similar style as struct iphdr, struct udphdr
struct socks5_reply_header {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
};

struct socks5_udp_header {
    uint16_t rsv;
    uint8_t frag;
    uint8_t atyp;
};

// https://datatracker.ietf.org/doc/html/rfc1928

// socks5 headers defaults
enum class ESOCKS5_DEFAULTS : std::uint8_t {
    RSV		     = 0x00,
    SUPPORT_AUTH = 0x01,
    VERSION		 = 0x05,
    VER_USERPASS = 0x01
};

// AUTH_Types (0x00 is default), NOAUTH is implemented only
enum class ESOCKS5_AUTH_TYPES : std::uint8_t {
    NOAUTH   = 0x00,
    USERPASS = 0x02,
};

// socks5 client connection request commands
// 4.  Requests
//     o  VER    protocol version: X'05'
//     o  CMD
//          o  CONNECT       X'01'
//          o  BIND          X'02'
//          o  UDP ASSOCIATE X'03'
// UDP_ASSOCIATE and TCP_IP_STREAM is supported only
enum class ESOCKS5_CONNECTION_CMD : std::uint8_t {
    TCP_STREAM	  = 0x01,
    TCP_PORT_BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

// 4.  Requests
// o  RSV    RESERVED
// o  ATYP   address type of following address
//      o  IP V4 address: X'01'
//      o  DOMAINNAME:    X'03'
//      o  IP V6 address: X'04'
enum class ESOCKS5_ADDR_TYPE : std::uint8_t {
    IPv4   = 0x01, // only this one implemented
    DOMAIN = 0x03,
    IPv6   = 0x04
};
