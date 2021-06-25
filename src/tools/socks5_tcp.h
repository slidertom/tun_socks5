#pragma once

#include <utility>
#include <bits/stdc++.h>

struct in_addr;

int socks5_client_greeting_no_auth(int fdSoc) noexcept;

std::pair<struct in_addr, uint16_t> socks5_udp_connection_request(int fdSock) noexcept;

bool socks5_get_udp_bind_params(const char *socks5_server, uint16_t socks5_port,
                                int &fdSoc, struct in_addr &addr, uint16_t &port) noexcept;

int socks5_tcp_client_connection_request(int net_serv_fd,
                                         const std::string& destination_addr, const std::uint16_t& destination_port) noexcept;
