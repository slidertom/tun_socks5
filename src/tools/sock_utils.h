#pragma once

#include <bits/stdc++.h>
#include <stdio.h>
#include <netinet/in.h>

namespace sock_utils
{
    void get_socket_info(int fdSoc, struct sockaddr_in &addr) noexcept;

    void print_socket_info(int fdSoc) noexcept;

    void check_socket(int fdSoc) noexcept;

    int create_udp_socket(struct in_addr *inp, uint16_t dport) noexcept;

    int read_data(int fdSoc, char *buffer, size_t buff_read_len, int recv_flag) noexcept;

    size_t write_data(int fdSoc, const char *buffer, size_t buff_write_len, int send_flags) noexcept;

    int close_connection(int fdSoc) noexcept;

    int create_tcp_socket_client(const char *name, std::uint16_t port) noexcept;
}
