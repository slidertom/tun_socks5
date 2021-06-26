#pragma once

#include <bits/stdc++.h>
#include "IPv4.h"

bool socks5_send_udp_packet(int fdSoc, unsigned char *buffer, size_t size) noexcept;
bool socks5_send_udp_packet_to_tun(int fdTun, unsigned char *buffer, size_t size,
                                   uint32_t tun_ip,
                                   const Ipv4ConnMap &map_dst_to_connn) noexcept;
