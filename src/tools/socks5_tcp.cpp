#include "socks5_tcp.h"

#include "sock_utils.h"
#include "socks5_defs.h"
#include "IPv4.h"

#include <vector>
#include <stdio.h>

int socks5_tcp::client_greeting_no_auth(int fdSoc) noexcept
{
	// [VERSION, NAUTH, AUTH]
	std::vector<char> client_greeting_msg = {
		static_cast<char>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<char>(ESOCKS5_DEFAULTS::SUPPORT_AUTH),
		static_cast<char>(ESOCKS5_AUTH_TYPES::NOAUTH)
	};

	const int write_ret = sock_utils::write_data(fdSoc, client_greeting_msg.data(), client_greeting_msg.size(), 0);

	std::vector<char> server_choice(2);
	const int read_ret = sock_utils::read_data(fdSoc, server_choice.data(), server_choice.size(), 0);
	if (server_choice.at(0) == 0x05 &&
        server_choice.at(1) == 0x00) {
		return 0;
	}
    else {
		return -1;
	}

	return 0;
}

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
	std::vector<char> client_connection_request = {
		static_cast<char>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<char>(ESOCKS5_CONNECTION_CMD::UDP_ASSOCIATE),
		static_cast<char>(ESOCKS5_DEFAULTS::RSV),
		static_cast<char>(ESOCKS5_ADDR_TYPE::IPv4),
		static_cast<char>(ipv4_buffer[0]),
		static_cast<char>(ipv4_buffer[1]),
		static_cast<char>(ipv4_buffer[2]),
		static_cast<char>(ipv4_buffer[3]),
	};

	client_connection_request.push_back(static_cast<char>(destination_port>>8));
	client_connection_request.push_back(static_cast<char>(destination_port));

	int write_ret = sock_utils::write_data(fdSock, client_connection_request.data(), client_connection_request.size(), 0);

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
	std::vector<char> server_response(reply_bytes);
	const int read_ret = sock_utils::read_data(fdSock, server_response.data(), server_response.size(), 0);
    read_ret;

	if (server_response.at(0) == 0x05 &&
        server_response.at(1) == 0x00) {
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
    std::cout << "Socket has started:" << fdSoc << std::endl;

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
	int inet_ret = inet_pton(AF_INET, destination_addr.c_str(), ipv4_buffer);

	std::vector<char> client_connection_request = {
		static_cast<char>(ESOCKS5_DEFAULTS::VERSION),
		static_cast<char>(ESOCKS5_CONNECTION_CMD::TCP_STREAM),
		static_cast<char>(ESOCKS5_DEFAULTS::RSV),
		static_cast<char>(ESOCKS5_ADDR_TYPE::IPv4),
		static_cast<char>(ipv4_buffer[0]),
		static_cast<char>(ipv4_buffer[1]),
		static_cast<char>(ipv4_buffer[2]),
		static_cast<char>(ipv4_buffer[3]),
	};
	client_connection_request.push_back(static_cast<char>(destination_port>>8));
	client_connection_request.push_back(static_cast<char>(destination_port));

	int write_ret = sock_utils::write_data(fdSoc, client_connection_request.data(), client_connection_request.size(), 0);

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
	std::vector<char> server_responce(reply_bytes);
	int read_ret = sock_utils::read_data(fdSoc, server_responce.data(), server_responce.size(), 0);

	if (server_responce.at(0) == 0x05 && server_responce.at(1) == 0x00) {
		return 0;
	}
	else {
		return -1;
	}
}

