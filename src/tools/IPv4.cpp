#include "IPv4.h"

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

#include "socks5_udp.h"
#include "console_colors.h"

bool ipv4::is_udp(const std::byte *buffer) noexcept
{
	struct iphdr *iph = (struct iphdr *)buffer;
	if (iph->protocol == IPPROTO_UDP) {
        return true;
	}
    return false;
}

// https://github.com/joshlong/interesting-native-code-examples/blob/master/packet_sniffer.c
/*
static void PrintData(unsigned char *data, size_t Size)
{
	for (size_t i = 0; i < Size; ++i) {
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

		if (i == Size - 1) { // print the last spaces
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
*/
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
	std::cout << "   |-IP Total Length   : " << ntohs(iph->tot_len) << "Bytes(Size of Packet)" << std::endl;
	std::cout << "   |-Identification    : " << ntohs(iph->id)               << std::endl;
	std::cout << "   |-TTL               : " << (unsigned int)iph->ttl       << std::endl;
	std::cout << "   |-Protocol          : " << (unsigned int)iph->protocol  << std::endl;
	std::cout << "   |-Checksum          : " << ::ntohs(iph->check)          << std::endl;
	std::cout << "   |-Source IP         : " << ::inet_ntoa(source.sin_addr) << std::endl;
	std::cout << "   |-Destination IP    : " << ::inet_ntoa(dest.sin_addr)   << std::endl;


	/* // TCP
	const unsigned short iphdrlen = iph->ihl*4;
    std::cout << "IP Header" << std::endl;
	PrintData(buffer, iphdrlen);

	std::cout << "TCP Header" << std::endl;
	PrintData(buffer + iphdrlen, tcph->doff*4);

	std::cout << "Data Payload" << std::endl;
	PrintData(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4) );
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

void map_udp_packet(const std::byte *buffer, size_t size, Ipv4ConnMap &map_dst_to_conn)
{
    struct iphdr *iph = (struct iphdr *)buffer;
    unsigned short iphdrlen = (unsigned short)iph->ihl*4;

    addr_ipv4 source, dest;
    source.addr = iph->saddr;
    dest.addr   = iph->daddr;

    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen);
    source.port = ::ntohs(udph->uh_sport);
    dest.port   = ::ntohs(udph->uh_dport);

    auto src_conn = std::make_pair(source, dest);
    map_dst_to_conn[dest] = src_conn;
}

int recvData(int fd, void *data, int len)
{
    char *ptr = (char *)data;
    int total = 0;

    while (len > 0)
    {
        int recvd = ::recv(fd, ptr, len, 0);
        if (recvd < 0) {
            return -1;
        }

        if (recvd == 0) {
            return -1;
        }

        ptr += recvd;
        len -= recvd;
        total -= recvd;
    }

    return total;
}
