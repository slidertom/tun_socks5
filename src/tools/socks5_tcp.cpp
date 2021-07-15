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

struct pseudoheader {
	uint32_t src;
	uint32_t dst;
	uint8_t zero;
	uint8_t proto;
	uint16_t length;
};

unsigned short
checksum(void *buf, int len)
{
	int i;
	unsigned short *data;
	unsigned int sum;

	sum = 0;
	data = (unsigned short *)buf;
	for (i = 0; i < len - 1; i += 2)
	{
		sum += *data;
		data++;
	}

	if (len & 1)
		sum += ((unsigned char*)buf)[i];

	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

unsigned short
tcp_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr)
{
	char buf[sizeof(struct pseudoheader) + sizeof(struct tcphdr)];
	struct pseudoheader *phdr;

	phdr = (struct pseudoheader *)buf;
	phdr->src    = iphdr->saddr;
	phdr->dst    = iphdr->daddr;
	phdr->zero   = 0;
	phdr->proto  = IPPROTO_TCP;
	phdr->length = htons(sizeof(struct tcphdr));

	memcpy(&buf[sizeof(struct pseudoheader)], tcphdr, sizeof(struct tcphdr));

	return checksum(buf, sizeof(struct pseudoheader) + sizeof(struct tcphdr));
}

unsigned int compute_cksum(unsigned short int * cksum_arr)
{
  unsigned int i,sum=0, cksum;

  for (i=0;i<12;i++)               // Compute sum
    sum = sum + cksum_arr[i];

  cksum = sum >> 16;              // Fold once
  sum = sum & 0x0000FFFF;
  sum = cksum + sum;

  cksum = sum >> 16;             // Fold once more
  sum = sum & 0x0000FFFF;
  cksum = cksum + sum;

  /* XOR the sum for checksum */
  printf("Checksum Value: 0x%04X\n", (0xFFFF^cksum)); //print result
  return (cksum);
}

// Generic checksum calculation function
unsigned short csum(unsigned short *ptr,int nbytes)
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

#define PACKET_WINDOW_SIZE 256
#define PACKET_TTL 128

bool socks5_tcp::send_packet_to_tun(int fdTun,
                                    const std::byte *buffer, size_t payload_size,
                                    uint32_t tun_ip,
                                    uint32_t saddr,
                                    uint16_t dport,
                                    const Ipv4ConnMap &map_dst_to_conn) noexcept
{
    constexpr unsigned short iphdrlen  = sizeof(struct iphdr);
    constexpr unsigned short tcphdrlen = sizeof(struct tcphdr);
    const size_t pack_size = iphdrlen + tcphdrlen + payload_size;
	std::byte *out_data = (std::byte *)::malloc(pack_size);
	::memset(out_data, 0, pack_size);
	struct iphdr *iphdr   = (struct iphdr*)out_data;
	struct tcphdr *tcphdr = (struct tcphdr*)&out_data[sizeof(struct iphdr)];

    iphdr->ihl      = 5;
    iphdr->version  = 4;
    iphdr->tos      = 0x0;
    iphdr->frag_off = htons(0x4000); // Don't fragment
    iphdr->id       = 0;
    iphdr->ttl      = PACKET_TTL; // hops
    iphdr->tot_len  = ::htons(pack_size);
    iphdr->protocol = IPPROTO_TCP;
    iphdr->saddr    = saddr;
    iphdr->daddr    = tun_ip;
    iphdr->check    = 0;

    tcphdr->th_sport = htons(80);
    tcphdr->th_dport = dport;
    tcphdr->th_seq   = htonl(1);
    tcphdr->doff    = 0x5;
	tcphdr->window  = ::htons(PACKET_WINDOW_SIZE);
    //tcphdr->th_ack   = 0;
    //tcphdr->th_off   = 5;
    //tcphdr->syn = 1;
    //tcphdr->ack = 0;
    //tcphdr->th_win = htons(32767);
    tcphdr->check   = 0; // Done by kernel
    tcphdr->urg_ptr = 0;

    tcphdr->check = tcp_checksum(iphdr, tcphdr);
    iphdr->check  = checksum(iphdr, sizeof(struct iphdr));

    ::memcpy(out_data + (iphdrlen + tcphdrlen), buffer, payload_size);

    ipv4::print_ip_header((std::byte *)out_data, pack_size);
    const int nRet = ::write(fdTun, out_data, pack_size);

	::free(out_data);

	return nRet != -1;
}

// 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
// https://stackoverflow.com/questions/1295921/setting-the-maximum-segment-size-in-the-tcp-header

enum class ETCP_RESPONSE_TYPE
{
    SYN_ACK = 0,
    RST = 1,
    ACK = 2,
};

char *generate_tcp(struct iphdr *src_iphdr, struct tcphdr *src_tcphdr, ETCP_RESPONSE_TYPE type)
{
    #define PACKET_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))
	unsigned char *buf = (unsigned char *)::malloc(PACKET_LEN);
	::memset(buf, 0, PACKET_LEN);
	struct iphdr *iphdr   = (struct iphdr*)buf;
	struct tcphdr *tcphdr = (struct tcphdr*)&buf[sizeof(struct iphdr)];

	iphdr->version  = 0x4;
	iphdr->ihl      = 0x5;
	iphdr->tos      = 0;
	iphdr->tot_len  = ::htons(PACKET_LEN);
	iphdr->id       = 0;
	iphdr->frag_off = htons(IP_DF);
	iphdr->ttl      = PACKET_TTL;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check    = 0;
	iphdr->saddr    = src_iphdr->daddr;
	iphdr->daddr    = src_iphdr->saddr;

	tcphdr->source  = src_tcphdr->dest;
	tcphdr->dest    = src_tcphdr->source;
	tcphdr->doff    = 0x5;
	tcphdr->window  = ::htons(PACKET_WINDOW_SIZE);
	tcphdr->check   = 0;
	tcphdr->urg_ptr = 0;

	// TODO: switch/case
	if (type == ETCP_RESPONSE_TYPE::RST) {
		tcphdr->rst = 1;
	}
	else if (type == ETCP_RESPONSE_TYPE::ACK) {
        tcphdr->syn = 0;
        tcphdr->ack = 1;
        tcphdr->ack_seq = ::htonl(::htonl(src_tcphdr->seq) + 1);
	}
	else {
		tcphdr->syn = 1;
		tcphdr->ack = 1;
		tcphdr->ack_seq = ::htonl(::htonl(src_tcphdr->seq) + 1);
		tcphdr->seq     = src_tcphdr->seq;
	}

	tcphdr->check = tcp_checksum(iphdr, tcphdr);
	iphdr->check  = checksum(iphdr, sizeof(struct iphdr));

    ipv4::print_ip_header((std::byte *)buf, PACKET_LEN);
	return (char *)buf;
}

//https://github.com/cgutman/synner/blob/master/synner.c
void socks5_tcp::send_sync_ack_to_tun(int fdTun, std::byte *buffer, size_t size) noexcept
{
    struct iphdr *iph = (struct iphdr *)buffer;
    const unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

    char *buf = generate_tcp(iph, tcph, ETCP_RESPONSE_TYPE::SYN_ACK);
    int ret = ::write(fdTun, buf, PACKET_LEN);
    if (ret > 0) {

    }
    else {
        std::cout << "ERROR" << std::endl;
    }
    ::free(buf);
}

void socks5_tcp::send_ack_to_tun(int fdTun, uint32_t tun_ip, uint32_t saddr, uint16_t dport) noexcept
{
    // TODO: ACK
    // https://createnetech.tistory.com/25
	unsigned char *buf = (unsigned char *)::malloc(PACKET_LEN);
	::memset(buf, 0, PACKET_LEN);
	struct iphdr *iphdr   = (struct iphdr*)buf;
	struct tcphdr *tcphdr = (struct tcphdr*)&buf[sizeof(struct iphdr)];

	iphdr->version  = 0x4;
	iphdr->ihl      = 0x5;
	iphdr->tos      = 0;
	iphdr->tot_len  = ::htons(PACKET_LEN);
	iphdr->id       = 0;
	iphdr->frag_off = htons(IP_DF);
	iphdr->ttl      = PACKET_TTL;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check    = 0;
	iphdr->saddr    = saddr;
	iphdr->daddr    = tun_ip;

	tcphdr->source  = htons(80);
	tcphdr->dest    = dport;
	tcphdr->doff    = 0x5;
	tcphdr->window  = ::htons(PACKET_WINDOW_SIZE);
	tcphdr->check   = 0;
	tcphdr->urg_ptr = 0;

    tcphdr->syn = 0;
    tcphdr->ack = 1;
    tcphdr->ack_seq = htonl(1);;

	tcphdr->check = tcp_checksum(iphdr, tcphdr);
	iphdr->check  = checksum(iphdr, sizeof(struct iphdr));

    ipv4::print_ip_header((std::byte *)buf, PACKET_LEN);

    int ret = ::write(fdTun, buf, PACKET_LEN);
    if (ret > 0) {

    }
    else {
        std::cout << "ERROR" << std::endl;
    }
    ::free(buf);
}

