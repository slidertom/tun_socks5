#pragma once

#include <bits/stdc++.h>
#include "IPv4.h"

bool socks5_send_udp_packet(int fdSoc, unsigned char *buffer, size_t size) noexcept;
bool socks5_send_udp_packet_to_tun(int fdTun, unsigned char *buffer, size_t size,
                                   uint32_t tun_ip,
                                   const Ipv4ConnMap &map_dst_to_connn) noexcept;

// return false if socket creation fails
// { ip =>  tcp_socket, udp_socket }
class socks5_upd_socket
{
public:
    int m_fdSocket {-1};
};

bool socks5_send_udp_packet_ex(std::unordered_map<uint32_t, std::pair<int, socks5_upd_socket>> &dest_to_sock,
                               int &new_udp_sock,
                               unsigned char *buffer, size_t size,
                               const char *socks5_server, uint16_t socks5_port) noexcept;
