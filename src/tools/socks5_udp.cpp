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
bool socks5_send_udp_packet(int fdSoc, unsigned char *buffer, size_t size) noexcept
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
    char *out_data = (char *)::malloc(data_len);
        // Write header
        ::memcpy(out_data, &header, sizeof(header));
        out_data += sizeof(header);

        // Write DST
        ::memcpy(out_data, &iph->daddr,     sizeof(uint32_t));
        out_data += sizeof(uint32_t);
        ::memcpy(out_data, &udph->uh_dport, sizeof(uint16_t));
        out_data += sizeof(uint16_t);

        // Write payload
        unsigned char *data  = buffer + iphdrlen + sizeof(udph);
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

unsigned short csum(unsigned short *ptr,int nbytes)
{
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

/* function: ip_checksum_add
 * adds data to a checksum. only known to work on little-endian hosts
 * current - the current checksum (or 0 to start a new checksum)
 *   data        - the data to add to the checksum
 *   len         - length of data
 */
uint32_t ip_checksum_add(uint32_t current, const void *data, int len) {
    uint32_t checksum = current;
    int left = len;
    const uint16_t *data_16 = (const uint16_t *)data;
    while (left > 1) {
        checksum += *data_16;
        data_16++;
        left -= 2;
    }
    if (left) {
        checksum += *(uint8_t*)data_16;
    }
    return checksum;
}
/* function: ipv4_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp headers
 *   ip      - the ipv4 header
 *   len     - the transport length (transport header + payload)
 */
uint32_t ipv4_pseudo_header_checksum(const struct iphdr* ip, uint16_t len) {
    uint16_t temp_protocol, temp_length;
    temp_protocol = htons(ip->protocol);
    temp_length = htons(len);
    uint32_t current = 0;
    current = ip_checksum_add(current, &(ip->saddr), sizeof(uint32_t));
    current = ip_checksum_add(current, &(ip->daddr), sizeof(uint32_t));
    current = ip_checksum_add(current, &temp_protocol, sizeof(uint16_t));
    current = ip_checksum_add(current, &temp_length, sizeof(uint16_t));
    return current;
}

uint16_t checksum2(const void* buf, size_t buflen)
{
    uint32_t r = 0;
    size_t len = buflen;

    const uint16_t* d = reinterpret_cast<const uint16_t*>(buf);

    while (len > 1)
    {
        r += *d++;
        len -= sizeof(uint16_t);
    }

    if (len)
    {
        r += *reinterpret_cast<const uint8_t*>(d);
    }

    while (r >> 16)
    {
        r = (r & 0xffff) + (r >> 16);
    }

    return static_cast<uint16_t>(~r);
}

uint16_t inet_csum(const void *buf, size_t hdr_len)
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

/* set tcp checksum: given IP header and tcp segment */
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
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
    tcphdrp->check = (unsigned short)sum;
}

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
static u16 ip_checksum_fold(u64 sum)
{
	while (sum & ~0xffffffffULL)
		sum = (sum >> 32) + (sum & 0xffffffffULL);
	while (sum & 0xffff0000ULL)
		sum = (sum >> 16) + (sum & 0xffffULL);

	return ~sum;
}

/* Add bytes in buffer to a running checksum. Returns the new
 * intermediate checksum. Use ip_checksum_fold() to convert the
 * intermediate checksum to final form.
 */
static u64 ip_checksum_partial(const void *p, size_t len, u64 sum)
{
	/* Main loop: 32 bits at a time.
	 * We take advantage of intel's ability to do unaligned memory
	 * accesses with minimal additional cost. Other architectures
	 * probably want to be more careful here.
	 */
	const u32 *p32 = (const u32 *)(p);
	for (; len >= sizeof(*p32); len -= sizeof(*p32))
		sum += *p32++;

	/* Handle un-32bit-aligned trailing bytes */
	const u16 *p16 = (const u16 *)(p32);
	if (len >= 2) {
		sum += *p16++;
		len -= sizeof(*p16);
	}
	if (len > 0) {
		const u8 *p8 = (const u8 *)(p16);
		sum += ntohs(*p8 << 8);	/* RFC says pad last byte */
	}

	return sum;
}

/* Calculates and returns IPv4 header checksum. */
u16 ipv4_checksum(void *ip_header, size_t ip_header_bytes)
{
	return ip_checksum_fold(
		ip_checksum_partial(ip_header, ip_header_bytes, 0));
}

//badvpn
static uint16_t badvpn_read_be16 (const char *c_ptr)
{
    const uint8_t *ptr = (const uint8_t *)c_ptr;
    return ((uint16_t)ptr[0] << 8) | ((uint16_t)ptr[1] << 0);
}

static uint16_t ipv4_checksum(const struct iphdr *header, const char *extra, uint16_t extra_len)
{
    uint32_t t = 0;

    for (uint16_t i = 0; i < sizeof(*header) / 2; i++) {
        t += badvpn_read_be16((const char *)header + 2 * i);
    }

    for (uint16_t i = 0; i < extra_len / 2; i++) {
        t += badvpn_read_be16((const char *)extra + 2 * i);
    }

    while (t >> 16) {
        t = (t & 0xFFFF) + (t >> 16);
    }

    return htons(~t);
}


bool socks5_send_udp_packet_to_tun(int fdTun, unsigned char *buffer, size_t size,
                                   uint32_t tun_ip,
                                   const Ipv4ConnMap &map_dst_to_connn) noexcept
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

    const uint16_t sport = ::ipv4_conn_map_get_src_port_by_dst(map_dst_to_connn, inaddr.s_addr, dport);
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

    char *out_data = (char *)::malloc(pack_size); // TODO: pay load size

    // The checksum should be calculated over the entire header with the checksum
    // field set to 0, so that's what we do
    ip.check    = 0;
    unsigned short payload = payload_size + udplen;
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
    ipv4::print_udp_packet((unsigned char *)out_data, pack_size);

    const int nRet = ::write(fdTun, out_data, pack_size);

	::free(out_data);

	return nRet != -1;
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

