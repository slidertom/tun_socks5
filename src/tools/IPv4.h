#pragma once

#include <bits/stdc++.h>
#include "unordered_map"

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

inline bool operator==(const struct addr_ipv4 &__x, const struct addr_ipv4 &__y) noexcept {
    if (__x.addr != __y.addr) {
        return false;
    }
    if (__x.port != __y.port) {
        return false;
    }
    return true;
}

struct addr_ipv4_hash {
    std::size_t operator()(const struct addr_ipv4 &p) const {
        std::size_t h = 0;
        hash_combine(h, p.addr);
        hash_combine(h, p.port);
        return h;
    }

private:
    template <class T>
    static inline void hash_combine(std::size_t &seed, const T &v) {
        std::hash<T> hasher;
        seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
};

using Ipv4ConnMap = std::unordered_map<struct addr_ipv4, struct addr_ipv4, struct addr_ipv4_hash>;

namespace ipv4
{
    bool is_udp(const std::byte *buffer) noexcept;
    bool is_tcp(const std::byte *buffer) noexcept;

    void print_udp_packet(const std::byte *buffer, size_t size) noexcept;
    void print_ip_header(const std::byte *buffer, size_t size) noexcept;

    addr_ipv4 map_udp_packet(const std::byte *buffer, size_t size, Ipv4ConnMap &map_dst_to_conn);

    inline uint16_t ipv4_conn_map_get_src_port_by_dst(const Ipv4ConnMap &map_dst_to_connn,
                                                      uint32_t daddr, uint32_t dport)
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
};
