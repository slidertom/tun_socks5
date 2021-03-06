#include "IPv4.h"

#include "socks5_udp.h"
#include "console_colors.h"

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

bool ipv4::is_udp(const std::byte *buffer) noexcept
{
	struct iphdr *iph = (struct iphdr *)buffer;
	if (iph->protocol == IPPROTO_UDP) {
        return true;
	}

    return false;
}

bool ipv4::is_tcp(const std::byte *buffer) noexcept
{
    struct iphdr *iph = (struct iphdr *)buffer;
	if (iph->protocol == IPPROTO_TCP) {
        return true;
	}

    return false;
}


// https://github.com/joshlong/interesting-native-code-examples/blob/master/packet_sniffer.c

void ipv4::print_data(unsigned char *data, size_t size) noexcept
{
	for (size_t i = 0; i < size; ++i) {
		if (i != 0 && i%16 == 0) {  // if one line of hex printing is complete...
			std::cout << "         ";
			for (size_t j = i-16; j < i; ++j) {
				if (data[j] >= 32 && data[j] <= 128) {
					std::cout << (unsigned char)data[j]; // if its a number or alphabet
				}
				else {
                    std::cout << "."; // otherwise print a dot
				}
			}
			std::cout << std::endl;
		}

        if (i%16 == 0) {
            std::cout << "   ";
        }

        std::cout << (unsigned int)data[i];

		if (i == size - 1) { // print the last spaces
			for (size_t j = 0; j < 15-i%16; ++j) {
                std::cout << "   "; // extra spaces
			}
			std::cout << "         ";
            for (size_t j = i - i%16; j <= i; ++j) {
                if (data[j]>=32 && data[j]<=128) {
                    std::cout << (unsigned char)data[j];
                }
                else {
                    std::cout << ".";
                }
            }
			std::cout << std::endl;
		}
	}
}

void ipv4::print_ip_header(const std::byte *buffer, size_t size) noexcept
{
	struct iphdr *iph = (struct iphdr *)buffer;

	struct sockaddr_in source, dest;

	::memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	::memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

    std::cout << std::endl;
	std::cout << "IP Header\n";
	std::cout << "   |-IP Version        : " << (unsigned int)iph->version << std::endl;
	std::cout << "   |-IP Header Length  : " << (unsigned int)iph->ihl << " DWORDS or ";
                                                 std::cout << ((unsigned int)(iph->ihl))*4 << " Bytes" << std::endl;
	std::cout << "   |-Type Of Service   : " << (unsigned int)iph->tos << std::endl;
	std::cout << "   |-IP Total Length   : " << ::ntohs(iph->tot_len) << "Bytes(Size of Packet)" << std::endl;
	std::cout << "   |-Identification    : " << ::ntohs(iph->id)               << std::endl;
	std::cout << "   |-TTL               : " << (unsigned int)iph->ttl       << std::endl;
	std::cout << "   |-Protocol          : " << (unsigned int)iph->protocol  << std::endl;
	std::cout << "   |-Checksum          : " << ::ntohs(iph->check)          << std::endl;
	std::cout << "   |-Source IP         : " << ::inet_ntoa(source.sin_addr) << std::endl;
	std::cout << "   |-Destination IP    : " << ::inet_ntoa(dest.sin_addr)   << std::endl;


	/* // TCP
	const unsigned short iphdrlen = iph->ihl*4;
    std::cout << "IP Header" << std::endl;
	PrintData((unsigned char *)buffer, iphdrlen);

	std::cout << "TCP Header" << std::endl;
	struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
	PrintData((unsigned char *)buffer + iphdrlen, tcph->doff*4);

	std::cout << "Data Payload" << std::endl;
	PrintData((unsigned char *)buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4) );
    */
}

void ipv4::print_udp_packet(const std::byte *buffer, size_t size) noexcept
{
    //print_ip_header(buffer, size);

    struct iphdr *iph = (struct iphdr *)buffer;
    unsigned short iphdrlen = (unsigned short)iph->ihl*4;

    struct sockaddr_in source, dest;
    ::memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    ::memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen);

    std::cout << GREEN;
    std::cout << ::inet_ntoa(source.sin_addr) << ":" << ::ntohs(udph->uh_sport);
    std::cout << " ==> ";
    std::cout << ::inet_ntoa(dest.sin_addr)   << ":" << ::ntohs(udph->uh_dport);
    std::cout << " LEN:" << size;
    std::cout << RESET;
    std::cout << std::endl;

	//std::cout << "IP Header" << std::endl;
	//PrintData(buffer, iphdrlen);

	//std::cout << "UDP Header" << std::endl;
	//PrintData(buffer + iphdrlen , sizeof(udph);

	//std::cout << "Data Payload" << std::endl;
	//PrintData(buffer + iphdrlen + sizeof(udph), (size - sizeof(udph) - iph->ihl*4));
}

addr_ipv4 ipv4::map_udp_packet(const std::byte *buffer, size_t size, Ipv4ConnMap &map_dst_to_conn)
{
    struct iphdr *iph = (struct iphdr *)buffer;
    unsigned short iphdrlen = (unsigned short)iph->ihl*4;

    addr_ipv4 source, dest;
    source.addr = iph->saddr;
    dest.addr   = iph->daddr;

    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen);
    source.port = ::ntohs(udph->uh_sport);
    dest.port   = ::ntohs(udph->uh_dport);

    map_dst_to_conn[dest] = source;

    return dest;
}
