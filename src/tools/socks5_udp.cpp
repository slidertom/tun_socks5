#include "socks5_udp.h"

#include <arpa/inet.h>
#include <stdio.h> //For standard things
#include <stdlib.h>    //malloc
#include <string.h>    //memset
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sock_utils.h"
#include "socks5_tcp.h"
#include "socks5_defs.h"
#include "console_colors.h"

/*
7. Procedure for UDP-based clients
      +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+
     The fields in the UDP request header are:
          o  RSV  Reserved X'0000'
          o  FRAG    Current fragment number
          o  ATYP    address type of following addresses:
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT       desired destination port
          o  DATA           user data
*/
bool socks5_udp::send_packet_to_socket(int fdSoc, const std::byte *buffer, size_t size) noexcept
{
    struct iphdr *iph = (struct iphdr *)buffer;
    unsigned short iphdrlen = (unsigned short)iph->ihl*4;
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen);

    struct socks5_udp_header header;
    header.rsv  = (uint16_t)ESOCKS5_DEFAULTS::RSV;  // RSV  Reserved X'0000'
    header.frag = (uint8_t)ESOCKS5_DEFAULTS::RSV;   // FRAG Current fragment number
    header.atyp = (uint8_t)ESOCKS5_ADDR_TYPE::IPv4; // currently ipv4 is supported only...

    const size_t header_size = sizeof(header);
    const size_t dst_size = sizeof(uint32_t) + sizeof(uint16_t);

    const int pay_load_size = (size - sizeof(udph) - iph->ihl * 4);
    size_t data_len = header_size;
       data_len += dst_size;
       data_len += pay_load_size;

    // TODO: replace with std::vector<char> or better reuse boost asio or lwip
    // main point low level view howto format packet
    std::byte *out_data = (std::byte *)::malloc(data_len);
        // Write header
        ::memcpy(out_data, &header, sizeof(header));
        out_data += sizeof(header);

        // Write DST
        ::memcpy(out_data, &iph->daddr,     sizeof(uint32_t));
        out_data += sizeof(uint32_t);
        ::memcpy(out_data, &udph->uh_dport, sizeof(uint16_t));
        out_data += sizeof(uint16_t);

        // Write payload
        const std::byte *data  = buffer + iphdrlen + sizeof(udph);
        ::memcpy(out_data, data, pay_load_size);
        out_data += pay_load_size;

        out_data -= data_len;
    // TODO: Determine total packet size in the buffer -> cannot exceed socks_mtu
    const int nRet = sock_utils::write_data(fdSoc, out_data, data_len, 0);
    ::free(out_data);

    if (nRet == -1) {
        return false;
    }

    return true;
}


static uint16_t inet_csum(const void *buf, size_t hdr_len)
{
    unsigned long sum = 0;
    const uint16_t *ip1;

    ip1 = (const uint16_t *)buf;
    while (hdr_len > 1) {
        sum += *ip1++;
        if (sum & 0x80000000)
          sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }

    while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

    return(~sum);
}

bool socks5_udp::send_packet_to_tun(int fdTun,
                                    const std::byte *buffer, size_t size,
                                    uint32_t tun_ip,
                                    const Ipv4ConnMap &map_dst_to_conn) noexcept
{
    // this is just for the learning purposes do use boost asio for production
    // https://www.ridgesolutions.ie/index.php/2019/06/06/boost-asio-simple-udp-send-packet-example/

    struct socks5_udp_header header;
    ::memcpy(&header.rsv, buffer, sizeof(uint16_t)); // RSV  Reserved X'0000'
    buffer += sizeof(uint16_t);
    ::memcpy(&header.frag, buffer, sizeof(uint8_t));
    buffer += sizeof(uint8_t);
    ::memcpy(&header.atyp, buffer, sizeof(uint8_t));
    buffer += sizeof(uint8_t);

    if ((ESOCKS5_ADDR_TYPE)header.atyp != ESOCKS5_ADDR_TYPE::IPv4)  {   // currently ipv4 is supported only...
        return false;
    }

    uint32_t daddr;
    ::memcpy(&daddr, buffer, sizeof(uint32_t));
    buffer += sizeof(uint32_t);

    uint16_t dport;
    ::memcpy(&dport, buffer, sizeof(uint16_t));
    buffer += sizeof(uint16_t);
    dport = ntohs(dport);

    size_t payload_size = size - sizeof(uint16_t) - (sizeof(uint8_t) * 2) - sizeof(uint32_t) - sizeof(uint16_t);

    struct in_addr inaddr;
    inaddr.s_addr = daddr;
    //std::cout << "Destination address: " << ::inet_ntoa(inaddr);
    //std::cout << ":" << dport << std::endl;

    const uint16_t sport = ::ipv4_conn_map_get_src_port_by_dst(map_dst_to_conn, inaddr.s_addr, dport);
    if (sport == 0) {
        std::cout << RED << "ERROR: ipv4_conn_map_get_src_port_by_dst failed to find src port.";
        std::cout << RESET << std::endl;
        return false;
    }

    constexpr unsigned short iphdrlen = sizeof(struct iphdr);
    constexpr unsigned short udplen   = sizeof(struct udphdr);
    const size_t pack_size = iphdrlen + udplen + payload_size;
    //https://www.binarytides.com/raw-udp-sockets-c-linux/
    struct iphdr ip;
    ip.ihl      = 5;
    ip.version  = 4;
    ip.tos      = 0x0;
    ip.frag_off = htons(0x4000); // Don't fragment
    ip.id       = 0;
    ip.ttl      = 64; // hops
    ip.tot_len  = htons(pack_size);
    ip.protocol = IPPROTO_UDP; // 17
    ip.saddr    = daddr;
    ip.daddr    = tun_ip;

    // https://www.binarytides.com/raw-udp-sockets-c-linux/
    struct udphdr udp_header;
    udp_header.source  = htons(dport);
    udp_header.dest    = htons(sport);
    udp_header.len     = htons(udplen + payload_size);
    udp_header.check   = 0;
    // checksum optional

    std::byte *out_data = (std::byte *)::malloc(pack_size); // TODO: pay load size

    // The checksum should be calculated over the entire header with the checksum
    // field set to 0, so that's what we do
    ip.check    = 0;
    //unsigned short payload = payload_size + udplen;
    //compute_tcp_checksum(&ip, &payload);
    ip.check    = ::inet_csum(&ip, sizeof(struct iphdr));

    ::memcpy(out_data, &ip, iphdrlen);
    out_data += iphdrlen;

    ::memcpy(out_data, &udp_header, udplen);
    out_data += udplen;

    ::memcpy(out_data, buffer, payload_size);

    out_data -= (iphdrlen + udplen);


    std::cout << "SOC => TUN ";
    //ipv4::print_ip_header((unsigned char *)out_data, pack_size);
    ipv4::print_udp_packet(out_data, pack_size);

    const int nRet = ::write(fdTun, out_data, pack_size);

	::free(out_data);

	return nRet != -1;
}
