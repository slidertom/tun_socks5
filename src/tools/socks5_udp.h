#pragma once

#include <bits/stdc++.h>
#include "IPv4.h"

namespace socks5_udp
{
    bool send_packet_to_socket(int fdSoc,
                               unsigned char *buffer, size_t size) noexcept;

    bool send_packet_to_tun(int fdTun,
                            unsigned char *buffer, size_t size,
                            uint32_t tun_ip,
                            const Ipv4ConnMap &map_dst_to_conn) noexcept;
}
