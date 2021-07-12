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
	phdr->src = iphdr->saddr;
	phdr->dst = iphdr->daddr;
	phdr->zero = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->length = htons(sizeof(struct tcphdr));

	memcpy(&buf[sizeof(struct pseudoheader)], tcphdr, sizeof(struct tcphdr));

	return checksum(buf, sizeof(struct pseudoheader) + sizeof(struct tcphdr));
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
    tcp.check   = 0; // Done by kernel
    tcp.urg_ptr = 0;

    std::byte *out_data = (std::byte *)::malloc(pack_size);

    // The checksum should be calculated over the entire header with the checksum
    // field set to 0, so that's what we do
    ip.check    = 0;
    ip.check    = ::inet_csum(&ip, sizeof(struct iphdr));

    tcp.check   = tcp_checksum(&ip, &tcp);

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


unsigned short compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {

    register unsigned long sum = 0;

    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);

    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

    //add the pseudo header

    //the source ip

    sum += (pIph->saddr>>16)&0xFFFF;

    sum += (pIph->saddr)&0xFFFF;

    //the dest ip

    sum += (pIph->daddr>>16)&0xFFFF;

    sum += (pIph->daddr)&0xFFFF;

    //protocol and reserved: 6

    sum += htons(IPPROTO_TCP);

    //the length

    sum += htons(tcpLen);



    //add the IP payload

    //initialize checksum to 0

    tcphdrp->check = 0;

    while (tcpLen > 1) {

        sum += * ipPayload++;

        tcpLen -= 2;

    }

    //if any bytes left, pad the bytes and add

    if(tcpLen > 0) {

        //printf("+++++++++++padding, %dn", tcpLen);

        sum += ((*ipPayload)&htons(0xFF00));

    }

      //Fold 32-bit sum to 16 bits: add carrier to result

      while (sum>>16) {

          sum = (sum & 0xffff) + (sum >> 16);

      }

      sum = ~sum;

    //set computation result

    //tcphdrp->check = (unsigned short)sum;
      return (unsigned short)sum;

}

bool socks5_tcp::send_sync_to_tun(int fdTun, std::byte *buffer, size_t size) noexcept
{
    struct iphdr *iph = (struct iphdr *)buffer;
    const unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

    //uint32_t total_len = sizeof(struct iphdr )+sizeof(struct tcphdr);
    //iph->tot_len;

    /*
    struct in_addr daddr;
    daddr.s_addr = iph->daddr;
    struct in_addr saddr;
    saddr.s_addr = iph->saddr;
    std::cout << "Dst address: " << ::inet_ntoa(daddr) << "\n";
    std::cout << "Src address: " << ::inet_ntoa(saddr) << "\n";
    */

    std::swap(iph->saddr, iph->daddr);
    iph->check = 0;
    iph->check = ::inet_csum(iph, sizeof(struct iphdr)); // Ip checksum

    // TCP Header
    tcph->seq = ::htonl(0);
    tcph->ack = 1;
    //tcph->ack_seq = htonl(1); // ack number -> 1
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->urg = 0;
    tcph->urg_ptr = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->fin     = 0;
    //tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
    tcph->th_flags |= TH_SYN;
    tcph->th_flags |= TH_ACK;
    std::swap(tcph->source, tcph->dest);

    tcph->check = compute_tcp_checksum(iph,(unsigned short*)tcph);
    //tcph->check = 0; // Done by kernel

    int nRet = ::write(fdTun, buffer, size);
	if (nRet == -1) {
        std::cout << "ERROR\n";
	}
	return nRet != -1;
}

//bool send_ack_to_tun(int fdTun, std::byte *buffer, size_t size) noexcept;

struct tcpheader
{
	unsigned short int srcport; //16-bit source port
	unsigned short int destport; //16-bit destination port
	unsigned int seqnum; //32-bit sequence number
	unsigned int acknum; //32-bit acknowledgement number
	unsigned short int offset:4, //4-bit data offset or header length
		reserved:6, //6-bit reserved section
		//6-bit flags
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
	unsigned short int window;//16-bit receive window for flow control
	unsigned short int checksum;//6-bit checksum
	unsigned short int pointer;//16-bit urgent data pointer
	unsigned int option;//32-bit Options
};
// https://github.com/phaiyen0493/TCP_3_way_handshake_simulation/blob/main/server.c
void socks5_tcp::server_three_way_handshake(uint16_t client_port, int socket_fd, int rec_bytes, const char *buffer)
{
	// The server responds to the request by creating a connection granted TCP segment.
	struct tcpheader *TCP_segment = (struct tcpheader *)buffer;
	int header_length;
	if (rec_bytes > 0)
	{
		TCP_segment->srcport  = ::htons(80);
		TCP_segment->destport = ::ntohs(client_port);
		srand(time(NULL));
		TCP_segment->acknum  = TCP_segment->seqnum + 1;   // Assign acknowledgement number equal to initial client sequence number + 1
		TCP_segment->seqnum  = rand()% (int) (pow(2,32)); // Assign a random initial server sequence number
		header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
		//TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
		TCP_segment->reserved = 0;
		TCP_segment->urg = 0;
		TCP_segment->ack = 1; //Set ACK bit to 1
		TCP_segment->psh = 0;
		TCP_segment->rst = 0;
		TCP_segment->syn = 1; //Set SYN bit to 1
		TCP_segment->fin      = 0;
		TCP_segment->window   = 0;
		TCP_segment->checksum = 0;
		TCP_segment->pointer  = 0;
		TCP_segment->option   = 0;

		//Calculate checksum
		unsigned short int checksum_arr[12];
		unsigned int sum=0, checksum, wrap;

		memcpy(checksum_arr, TCP_segment, 24); //Copying 24 bytes

		for (int i=0;i<12;i++) {
			sum = sum + checksum_arr[i];
		}
		wrap = sum >> 16;// Wrap around once
		sum = sum & 0x0000FFFF;
		sum = wrap + sum;
		wrap = sum >> 16;// Wrap around once more
		sum = sum & 0x0000FFFF;
		checksum = wrap + sum;
		//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */
		//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));
		TCP_segment->checksum = checksum;

		int length = send(socket_fd, TCP_segment, 24, 0);
		if (length < 0) {
			printf("Fail to send SYN ACK signal to client\n");
		}
		else
		{
			//Print the values to console
			printf("\nServer has sent SYN ACK signal to client succesfully\n");
			printf("TCP source port: %d\n", TCP_segment->srcport);
			printf("TCP destination port: %d\n", TCP_segment->destport);
			printf("TCP sequence number: %d\n", TCP_segment->seqnum);
			printf("TCP ack number: %d\n", TCP_segment->acknum);
			printf("TCP offset/ header length: %d\n", TCP_segment->offset);
			printf("TCP URG bit value: %d\n", TCP_segment->urg);
			printf("TCP ACK bit value: %d\n", TCP_segment->ack);
			printf("TCP PSH bit value: %d\n", TCP_segment->psh);
			printf("TCP RST bit value: %d\n", TCP_segment->rst);
			printf("TCP SYN bit value: %d\n", TCP_segment->syn);
			printf("TCP FIN bit value: %d\n", TCP_segment->fin);
			printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
		}
	}

	memset(TCP_segment, 0, sizeof(struct tcpheader));	//reallocate memory
	//Once server receives ACK signal from client, TCP connection is created
	rec_bytes = recv(socket_fd, TCP_segment, sizeof(struct tcpheader), 0);
	if (rec_bytes > 0)
	{
		printf("\nServer received ACK signal from client. TCP connection is now created\n");
		//Print the values to console
		printf("TCP source port: %d\n", TCP_segment->srcport);
		printf("TCP destination port: %d\n", TCP_segment->destport);
		printf("TCP sequence number: %d\n", TCP_segment->seqnum);
		printf("TCP ack number: %d\n", TCP_segment->acknum);
		printf("TCP offset/ header length: %d\n", TCP_segment->offset);
		printf("TCP URG bit value: %d\n", TCP_segment->urg);
		printf("TCP ACK bit value: %d\n", TCP_segment->ack);
		printf("TCP PSH bit value: %d\n", TCP_segment->psh);
		printf("TCP RST bit value: %d\n", TCP_segment->rst);
		printf("TCP SYN bit value: %d\n", TCP_segment->syn);
		printf("TCP FIN bit value: %d\n", TCP_segment->fin);
		printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
	}
}

//initialize TCP header struct
struct tcp_hdr
{
    short int src;
    short int des;
    int seq;
    int ack;
    unsigned char tcph_reserved:4, tcph_offset:4;
    short int hdr_flags;
    short int rec;
     int cksum;
    short int ptr;
    int opt;
};

//bit flags for hdr_flags
enum {
	SYN = 0x01,
	ACK = 0x02,
	FIN = 0x04,
};
// https://github.com/caseycarroll/TCP-3-Way-Handshake-Demonstration/blob/master/server.c
// The server responds to the request by creating a connection granted TCP segment.
void print_tcp_seg(struct tcp_hdr *tcp_seg)
{
	FILE *fp;

	fp = fopen("server_output.txt", "a+");

	/*Print out tcp connection request */
	printf("source port:\t\t%hu\n", tcp_seg->src);
	printf("destination:\t\t%hu\n", tcp_seg->des);
	printf("sequence:\t\t%d\n", tcp_seg->seq);
	printf("acknowledgement:\t%d\n", tcp_seg->ack);

	if(tcp_seg->hdr_flags & SYN)
	{
		printf("hdr_flags: SYN = 1\n");
	} if (tcp_seg->hdr_flags & ACK)
	{
		printf("hdr_flags: ACK = 1\n");
	} if (tcp_seg->hdr_flags & FIN)
	{
		printf("hdr_flags: FIN = 1\n");
	}

	printf("hdr flags:\t\t0x0%x\n", tcp_seg->hdr_flags);
	printf("receive window:\t\t%hu\n", tcp_seg->rec);
	printf("checksum:\t\t0x%X\n", (0xFFFF^tcp_seg->cksum));
	printf("data pointer:\t\t%hu\n", tcp_seg->ptr);
	printf("options:\t\t%d\n", tcp_seg->opt);
	printf("-----------\n\n");

	  /* Print to file */
	fprintf(fp, "source port:\t\t%hu\n", tcp_seg->src);
  	fprintf(fp,"destination:\t\t%hu\n", tcp_seg->des);
  	fprintf(fp,"sequence:\t\t%d\n", tcp_seg->seq);
  	fprintf(fp,"acknowledgement:\t%d\n", tcp_seg->ack);

  	if(tcp_seg->hdr_flags & SYN)
  	{
    	fprintf(fp,"hdr_flags: SYN = 1\n");
  	} if (tcp_seg->hdr_flags & ACK)
  	{
    	fprintf(fp,"hdr_flags: ACK = 1\n");
  	} if (tcp_seg->hdr_flags & FIN)
  	{
    	fprintf(fp,"hdr_flags: FIN = 1\n");
  	}

  	fprintf(fp,"hdr flag actual value:\t\t0x0%x\n", tcp_seg->hdr_flags);
  	fprintf(fp,"receive window:\t\t%hu\n", tcp_seg->rec);
  	fprintf(fp,"checksum:\t\t0x%04X\n", (0xFFFF^tcp_seg->cksum));
  	fprintf(fp,"data pointer:\t\t%hu\n", tcp_seg->ptr);
  	fprintf(fp,"options:\t\t%d\n", tcp_seg->opt);
  	fprintf(fp,"-----------\n\n");

  	fclose(fp);

	return;
}
#define SERVER_SEQ 200
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
int socks5_tcp::recv_conn_req(int accept_sock, int num_data_recv, char *buffer)
{
	int num_sent, temp_portno;
	struct tcp_hdr tcp_seg;
	unsigned short int cksum_arr[12];

	memcpy(&tcp_seg, buffer, sizeof(tcp_seg));

	printf("-----CONNECTION REQUEST SEGMENT FROM CLIENT-----\n");
	print_tcp_seg(&tcp_seg);

	//set SYN bit to and ACK bit to 1
	tcp_seg.hdr_flags = (SYN | ACK);

	//Assign an initial server sequence number with an acknowledgement number equal to initial client sequence number + 1
	tcp_seg.ack = tcp_seg.seq + 1; //101
	tcp_seg.seq = SERVER_SEQ; //200

	temp_portno = tcp_seg.src;
	tcp_seg.src = tcp_seg.des;
	tcp_seg.des = temp_portno; //change the source and destination to go back to client

	/* compute checksum */
	memcpy(cksum_arr, &tcp_seg, 24); //Copying 24 bytes
  	tcp_seg.cksum = compute_cksum(cksum_arr); //compute checksum
  	printf("0x%04X\n", (0xFFFF^tcp_seg.cksum));

  	printf("-----CONNECTION ACCEPTED SEGMENT TO CLIENT-----\n");
  	print_tcp_seg(&tcp_seg);

	/* send connection granted segment to client */
	memcpy(buffer, &tcp_seg, sizeof tcp_seg);	//copy segment to char buffer
	num_sent = write(accept_sock, buffer, 255); //send buffer to client
	if (num_sent < 0)
	{
	  printf("error writing to socket...\n");
	  exit(1);
	}
	return 0;
}

// https://github.com/5G-Measurement/raw-tcp/blob/7402b098f1fd53078c4a8fa512459f601893684a/packet.h
#define MTU 1440
struct trans_packet_state {
    unsigned int seq;
    unsigned int ack;
};

struct packet_info {
    char dest_ip[128];
    char source_ip[128];
    uint16_t dest_port;
    uint16_t source_port;
    struct trans_packet_state state;
};
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

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
/*
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
*/

// https://stackoverflow.com/questions/1295921/setting-the-maximum-segment-size-in-the-tcp-header
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct tcp_option_mss {
    uint8_t kind; /* 2 */
    uint8_t len; /* 4 */
    uint16_t mss;
} __attribute__((packed));

int send_packet(struct packet_info* packetinfo, int fdSoc, uint16_t window,
                uint16_t id, uint32_t seg)
{
    char datagram[MTU]; //Datagram to represent the packet TODO

    //zero out the packet buffer
    ::memset(datagram, 0, MTU);
    struct iphdr *iph = (struct iphdr *)datagram; // IP header
    constexpr unsigned short iphdrlen = sizeof(struct iphdr);
    //constexpr unsigned short ip_len2 = sizeof(ip);
    struct tcphdr *tcph = (struct tcphdr *)(datagram + iphdrlen); // TCP header

    int pack_size = iphdrlen + sizeof(struct tcphdr);

    // Fill in the IP Header
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0x0;
    iph->tot_len  = ::htons(pack_size);
    iph->id       = id;
    iph->frag_off = 0;
    iph->ttl      = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr    = inet_addr(packetinfo->source_ip);    //Spoof the source ip address
    iph->daddr    = inet_addr(packetinfo->dest_ip);

    // TCP Header
    tcph->source  = packetinfo->source_port;
    tcph->dest    = packetinfo->dest_port;
    tcph->seq     = seg;
    tcph->doff    = sizeof(struct tcphdr)/4; //tcph->doff    = 5;  // tcp header size
    tcph->fin     = 0;
    tcph->rst     = 0;
    tcph->psh     = 0;
    tcph->urg     = 0;
    tcph->res1    = 0;
    tcph->res2    = 0;
    tcph->window  = window;
    tcph->check   = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    //if (flag == REPLY_SYN_ACK) {
    tcph->seq = 0;
    tcph->ack_seq = htonl(1);
    tcph->syn = 1;
    tcph->ack = 1;
    tcph->th_flags |= TH_SYN;
    tcph->th_flags |= TH_ACK;
    //

    tcph->check = 0;
    tcph->check = compute_tcp_checksum(iph,(unsigned short*)tcph);

    iph->check    = 0;  //Set to 0 before calculating checksum
    iph->check    = ::inet_csum(iph, sizeof(struct iphdr)); // Ip checksum

    int ret = ::write(fdSoc, datagram, pack_size);

    if (ret > 0) {
        return 1;
    }
    else {
        return -1;
    }
}


#define PACKET_TTL 128
#define PACKET_WINDOW_SIZE 256
char *generate_tcp(struct iphdr *src_iphdr, struct tcphdr *src_tcphdr, int rst)
{
    #define PACKET_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))
	unsigned char *buf;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	char ipstr[INET_ADDRSTRLEN];

	buf = (unsigned char *)malloc(PACKET_LEN);
	if (buf == NULL)
		return NULL;

	memset(buf, 0, PACKET_LEN);
	iphdr  = (struct iphdr*)buf;
	tcphdr = (struct tcphdr*)&buf[sizeof(struct iphdr)];

	iphdr->version = 0x4;
	iphdr->ihl = 0x5;
	iphdr->tos = 0;
	iphdr->tot_len = htons(PACKET_LEN);
	iphdr->id = 0;
	iphdr->frag_off = htons(IP_DF);
	iphdr->ttl      = PACKET_TTL;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check = 0;
	iphdr->saddr = src_iphdr->daddr;
	iphdr->daddr = src_iphdr->saddr;

	tcphdr->source  = src_tcphdr->dest;
	tcphdr->dest    = src_tcphdr->source;
	tcphdr->doff    = 0x5;
	tcphdr->window  = htons(PACKET_WINDOW_SIZE);
	tcphdr->check   = 0;
	tcphdr->urg_ptr = 0;

	if (rst) {
		tcphdr->rst = 1;
	}
	else {
		tcphdr->syn = 1;
		tcphdr->ack = 1;
		tcphdr->ack_seq = htonl(htonl(src_tcphdr->seq) + 1);
		tcphdr->seq = src_tcphdr->seq;
	}

	tcphdr->check = tcp_checksum(iphdr, tcphdr);
	iphdr->check  = checksum(iphdr, sizeof(struct iphdr));

	inet_ntop(AF_INET, &iphdr->daddr, ipstr, INET_ADDRSTRLEN);
	printf("SYN from %s on port %d\n", ipstr, htons(tcphdr->source));

	return (char *)buf;
}

//https://github.com/cgutman/synner/blob/master/synner.c
void socks5_tcp::send_sync_ack_to_tun(int fdTun, std::byte *buffer, size_t size) noexcept
{
    struct iphdr *iph = (struct iphdr *)buffer;
    const unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
    /*
    struct in_addr daddr;
    daddr.s_addr = iph->daddr;
    struct in_addr saddr;
    saddr.s_addr = iph->saddr;

    // Server replies SYN + ACK
    struct packet_info packet;
    packet.state.seq = 1;
    packet.state.ack = 1;
    strcpy(packet.dest_ip,   inet_ntoa(saddr));
    strcpy(packet.source_ip, inet_ntoa(daddr));

    packet.dest_port   = tcph->source;
    packet.source_port = tcph->dest;
    send_packet(&packet, fdTun, tcph->window, iph->id, htonl(ntohl(tcph->seq) +1));
    */
    char *buf = generate_tcp(iph, tcph, 0);
    int ret = ::write(fdTun, buf, PACKET_LEN);
    if (ret > 0) {

    }
    else {
        std::cout << "ERROR" << std::endl;
    }
    free(buf);
}


