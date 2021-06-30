#pragma once

#include <bits/stdc++.h>

namespace ipv4 {
    bool is_udp(const std::byte *buffer) noexcept;
    void print_udp_packet(const std::byte *buffer, size_t size) noexcept;
    void print_ip_header(const std::byte *buffer, size_t size) noexcept;
};

struct addr_ipv4 {
    uint32_t addr;
    uint16_t port;
};

// operator < required for map (stl_function.h)
inline bool operator<(const struct addr_ipv4 &__x, const struct addr_ipv4 &__y) noexcept {
    if (__x.addr != __y.addr) {
        return __x.addr < __y.addr;
    }
    if (__x.port != __y.port) {
        return __x.port < __y.port;
    }
    return false;
}

#include "map"

using Ipv4ConnMap = std::map<struct addr_ipv4, struct addr_ipv4>;
inline uint16_t ipv4_conn_map_get_src_port_by_dst(const Ipv4ConnMap &map_dst_to_connn, uint32_t daddr, uint32_t dport)
{
    addr_ipv4 dst_addr;
    dst_addr.addr = daddr;
    dst_addr.port = dport;
    const auto found = map_dst_to_connn.find(dst_addr);
    if ( found == map_dst_to_connn.end() ) {
        return 0;
    }
    return found->second.port;
}
addr_ipv4 map_udp_packet(const std::byte *buffer, size_t size, Ipv4ConnMap &map_dst_to_conn);


