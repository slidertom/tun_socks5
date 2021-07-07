#include "socks5_tcp.h"

#include "sock_utils.h"
#include "socks5_defs.h"
#include "IPv4.h"

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <vector>
#include <stdio.h>

static bool socks5_check_server_response(const std::vector<std::byte> &response)
{
    if (response.size() < 2) {
        return false;
    }

    if ((char)response.at(0) == 0x05 &&
        (char)response.at(1) == 0x00) {
		return true;
	}

	return false;
}

int socks5_tcp::client_greeting_no_auth(int fdSoc) noexcept
{
	// [VERSION, NAUTH, AUTH]
	std::vector<std::byte> client_greeting_msg = {
		static_cast<std::byte>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<std::byte>(ESOCKS5_DEFAULTS::SUPPORT_AUTH),
		static_cast<std::byte>(ESOCKS5_AUTH_TYPES::NOAUTH)
	};

	const int write_ret = sock_utils::write_data(fdSoc, client_greeting_msg.data(), client_greeting_msg.size(), 0);
	if (write_ret < 0) {
        return -1;
	}

	std::vector<std::byte> server_choice(2);
	const int read_ret = sock_utils::read_data(fdSoc, server_choice.data(), server_choice.size(), 0);
	if (read_ret < 0) {
        return -1;
	}

	if ( ::socks5_check_server_response(server_choice) ) {
		return 0;
	}
    else {
		return -1;
	}

	return 0;
}

/*
  Requests

   Once the method-dependent subnegotiation has completed, the client
   sends the request details.  If the negotiated method includes
   encapsulation for purposes of integrity checking and/or
   confidentiality, these requests MUST be encapsulated in the method-
   dependent encapsulation.

   The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order

   The SOCKS server will typically evaluate the request based on source
   and destination addresses, and return one or more reply messages, as
   appropriate for the request type.
*/
//https://stackoverflow.com/questions/49855516/telegram-calls-via-dante-socks5-proxy-server-not-working
/*
    Client instantiates a TCP socks5 connection.
    Client sends a UDP ASSOCIATE request, containing the client's source address and port,
    which will be used to send UDP datagrams to the socks5 Server.

    They might be zeros (in Telegram they are) (section 4).
    Socks5 Server binds a random UDP port for relaying datagrams for this TCP socks5 connection and sends a
    UDP ASSOCIATE response, containing the address and port where the client should send the datagrams to be relayed (section 6).
    To send a datagram, the Client must add a header to the payload, containing a destination address and port,
    where the server should relay that datagram (section 7).
    Server will keep the UDP port bound until the TCP socks5 connection terminates.

   As you can see, opening a single TCP port is not enough.
   For UDP to work correctly, the automatically bound UDP port must be reachable by client.
   NATs and Firewalls might further complicate the situation.
*/

static std::pair<struct in_addr, uint16_t> socks5_udp_connection_request(int fdSock) noexcept
{
	// The DST.ADDR and
    // DST.PORT fields contain the address and port that the client expects
    // to use to send UDP datagrams on for the association.
	// The server MAY use this information to limit access to the association.
	// Dante expects these values to be valid? ... (TODO: bind? open socket like server?)
	char ipv4_buffer[4];
	::memset(ipv4_buffer, 0, sizeof(ipv4_buffer));
    const uint16_t destination_port = 0;

    // [VERSION, SOCKS_CMD, RESV(0x00), (SOCKS5 Addr Type)[TYPE, ADDR], DST_PORT]
	std::vector<std::byte> client_connection_request = {
		static_cast<std::byte>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<std::byte>(ESOCKS5_CONNECTION_CMD::UDP_ASSOCIATE),
		static_cast<std::byte>(ESOCKS5_DEFAULTS::RSV),
		static_cast<std::byte>(ESOCKS5_ADDR_TYPE::IPv4),
		static_cast<std::byte>(ipv4_buffer[0]),
		static_cast<std::byte>(ipv4_buffer[1]),
		static_cast<std::byte>(ipv4_buffer[2]),
		static_cast<std::byte>(ipv4_buffer[3]),
	};

	client_connection_request.push_back(static_cast<std::byte>(destination_port>>8));
	client_connection_request.push_back(static_cast<std::byte>(destination_port));

	const int write_ret = sock_utils::write_data(fdSock, client_connection_request.data(), client_connection_request.size(), 0);
	if (write_ret < 0) {
        struct in_addr addr;
        return std::make_pair(addr, 0);
	}

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
	std::vector<std::byte> server_response(reply_bytes);
	const int read_ret = sock_utils::read_data(fdSock, server_response.data(), server_response.size(), 0);
    if (read_ret < 0) {
        struct in_addr addr;
        return std::make_pair(addr, 0);
    }

	if ( ::socks5_check_server_response(server_response) ) {
        // UDP_ASSOCIATE => UDP address and PORT to send requests
        void *addr_buffer = server_response.data() + sizeof(struct socks5_reply_header);
        struct addr_ipv4 ip4;
        ::memcpy(&ip4, addr_buffer, sizeof(ip4));
        struct in_addr addr = *(struct in_addr *)&ip4.addr;
        const uint16_t port = ::ntohs(ip4.port);
        return std::make_pair(addr, port);
	}

	struct in_addr addr;
	return std::make_pair(addr, 0);
}

bool socks5_tcp::get_udp_bind_params(const char *socks5_server, uint16_t socks5_port,
                                     int &fdSoc, struct in_addr &addr, uint16_t &port) noexcept
{
    fdSoc = sock_utils::create_tcp_socket_client(socks5_server, socks5_port);
    if (fdSoc == 0) {
        std::cout << "Socket start has failed: " << fdSoc << std::endl;
        return false;
    }
    std::cout << "Socket has started: " << fdSoc << std::endl;

    std::cout << "TCP Socket: ";
    sock_utils::print_socket_info(fdSoc);

    socks5_tcp::client_greeting_no_auth(fdSoc);
    auto udp_conn = ::socks5_udp_connection_request(fdSoc);
    if ( udp_conn.second == 0 ) {
        std::cout << "socks5_udp_connection_request failed" << std::endl;
        return false;
    }

    addr = udp_conn.first;
    port = udp_conn.second;

    return true;
}

int socks5_tcp::tcp_client_connection_request(int fdSoc,
                                              const std::string &destination_addr,
                                              const std::uint16_t &destination_port) noexcept
{
	// [VERSION, SOCKS_CMD, RESV(0x00), (SOCKS5 Addr Type)[TYPE, ADDR], DST_PORT]
	char ipv4_buffer[4];
	::inet_pton(AF_INET, destination_addr.c_str(), ipv4_buffer);

	std::vector<std::byte> client_connection_request = {
		static_cast<std::byte>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<std::byte>(ESOCKS5_CONNECTION_CMD::TCP_STREAM),
		static_cast<std::byte>(ESOCKS5_DEFAULTS::RSV),
		static_cast<std::byte>(ESOCKS5_ADDR_TYPE::IPv4),
		static_cast<std::byte>(ipv4_buffer[0]),
		static_cast<std::byte>(ipv4_buffer[1]),
		static_cast<std::byte>(ipv4_buffer[2]),
		static_cast<std::byte>(ipv4_buffer[3]),
	};
	client_connection_request.push_back(static_cast<std::byte>(destination_port>>8));
	client_connection_request.push_back(static_cast<std::byte>(destination_port));

	const int write_ret = sock_utils::write_data(fdSoc, client_connection_request.data(), client_connection_request.size(), 0);
	if (write_ret < 0) {
        return -1;
	}

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
	std::vector<std::byte> server_response(reply_bytes);
	const int read_ret = sock_utils::read_data(fdSoc, server_response.data(), server_response.size(), 0);
	if (read_ret < 0) {
        return -1;
	}

	if ( ::socks5_check_server_response(server_response) ) {
		return 0;
	}

	return -1;
}

int socks5_tcp::tcp_client_connection_request(int fdSoc,
                                              const std::uint32_t dst_addr,
                                              const std::uint16_t dst_port) noexcept
{
    std::uint8_t *ipv4_buffer = (std::uint8_t *)&dst_addr;

    std::vector<std::byte> client_connection_request = {
		static_cast<std::byte>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<std::byte>(ESOCKS5_CONNECTION_CMD::TCP_STREAM),
		static_cast<std::byte>(ESOCKS5_DEFAULTS::RSV),
		static_cast<std::byte>(ESOCKS5_ADDR_TYPE::IPv4),
		static_cast<std::byte>(ipv4_buffer[0]),
		static_cast<std::byte>(ipv4_buffer[1]),
		static_cast<std::byte>(ipv4_buffer[2]),
		static_cast<std::byte>(ipv4_buffer[3]),
	};
	client_connection_request.push_back(static_cast<std::byte>(dst_port>>8));
	client_connection_request.push_back(static_cast<std::byte>(dst_port));

	const int write_ret = sock_utils::write_data(fdSoc, client_connection_request.data(), client_connection_request.size(), 0);
	if (write_ret < 0) {
        return -1;
	}

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
	std::vector<std::byte> server_response(reply_bytes);
	const int read_ret = sock_utils::read_data(fdSoc, server_response.data(), server_response.size(), 0);
	if (read_ret < 0) {
        return -1;
	}

	if ( ::socks5_check_server_response(server_response) ) {
		return 0;
	}

	return -1;
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

bool socks5_tcp::send_packet_to_tun(int fdTun,
                                    const std::byte *buffer, size_t size,
                                    uint32_t tun_ip,
                                    uint32_t saddr,
                                    uint16_t dport,
                                    const Ipv4ConnMap &map_dst_to_conn) noexcept
{
    size_t payload_size = size;

    /*
    struct in_addr inaddr;
    inaddr.s_addr = daddr;
    //std::cout << "Destination address: " << ::inet_ntoa(inaddr);
    //std::cout << ":" << dport << std::endl;

    const uint16_t sport = ipv4::ipv4_conn_map_get_src_port_by_dst(map_dst_to_conn, inaddr.s_addr, dport);
    if (sport == 0) {
        std::cout << RED << "ERROR: ipv4_conn_map_get_src_port_by_dst failed to find src port.";
        std::cout << RESET << std::endl;
        return false;
    }
    */

    constexpr unsigned short iphdrlen  = sizeof(struct iphdr);
    constexpr unsigned short tcphdrlen = sizeof(struct tcphdr);
    const size_t pack_size = iphdrlen + tcphdrlen + payload_size;

    struct iphdr ip;
    ip.ihl      = 5;
    ip.version  = 4;
    ip.tos      = 0x0;
    ip.frag_off = htons(0x4000); // Don't fragment
    ip.id       = 0;
    ip.ttl      = 64; // hops
    ip.tot_len  = ::htons(pack_size);
    ip.protocol = IPPROTO_TCP;
    ip.saddr    = saddr;
    ip.daddr    = tun_ip;

    struct tcphdr tcp;
    tcp.th_sport = htons(80);
    tcp.th_dport = dport;
    tcp.th_seq   = htonl(1);
    tcp.th_ack   = 0;
    tcp.th_off   = 5;
    //tcp.syn = 1;
    //tcp.ack = 0;
    //tcp.th_win = htons(32767);
    tcp.check = 0; // Done by kernel
    tcp.urg_ptr = 0;

    std::byte *out_data = (std::byte *)::malloc(pack_size);

    // The checksum should be calculated over the entire header with the checksum
    // field set to 0, so that's what we do
    ip.check    = 0;
    ip.check    = ::inet_csum(&ip, sizeof(struct iphdr));

    ::memcpy(out_data, &ip, iphdrlen);
    out_data += iphdrlen;

    ::memcpy(out_data, &tcp, tcphdrlen);
    out_data += tcphdrlen;

    ::memcpy(out_data, buffer, payload_size);

    out_data -= (iphdrlen + tcphdrlen);

    //std::cout << "SOC => TUN ";
    //ipv4::print_ip_header((unsigned char *)out_data, pack_size);
    //ipv4::print_udp_packet(out_data, pack_size);

    const int nRet = ::write(fdTun, out_data, pack_size);

	::free(out_data);

	return nRet != -1;
}
