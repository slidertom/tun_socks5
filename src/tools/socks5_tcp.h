#pragma once

#include <utility>
#include <bits/stdc++.h>
#include "IPv4.h"

struct in_addr;

namespace socks5_tcp
{
    int client_greeting_no_auth(int fdSoc) noexcept;

    bool get_udp_bind_params(const char *socks5_server, uint16_t socks5_port,
                             int &fdSoc, struct in_addr &addr, uint16_t &port) noexcept;

    int tcp_client_connection_request(int fdSoc,
                                      const std::string &destination_addr,
                                      const std::uint16_t &destination_port) noexcept;

    int tcp_client_connection_request(int fdSoc,
                                      const std::uint32_t dst_addr,
                                      const std::uint16_t dst_port) noexcept;

    bool send_packet_to_tun(int fdTun,
                            const std::byte *buffer, size_t size,
                            uint32_t tun_ip,
                            uint32_t saddr,
                            uint16_t dport, // raw
                            const Ipv4ConnMap &map_dst_to_conn) noexcept;
    void send_sync_ack_to_tun(int fdTun, std::byte *buffer, size_t size) noexcept;
    void send_ack_to_tun(int fdTun, uint32_t tun_ip, uint32_t saddr, uint16_t dport) noexcept;
}
