#pragma once

#include <utility>
#include <bits/stdc++.h>

struct in_addr;

namespace socks5_tcp
{
    int client_greeting_no_auth(int fdSoc) noexcept;

    bool get_udp_bind_params(const char *socks5_server, uint16_t socks5_port,
                             int &fdSoc, struct in_addr &addr, uint16_t &port) noexcept;

    int tcp_client_connection_request(int fdSoc,
                                      const std::string &destination_addr,
                                      const std::uint16_t &destination_port) noexcept;
}
