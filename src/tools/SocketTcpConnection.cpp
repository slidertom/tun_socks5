#include "SocketTcpConnection.h"

#include "socks5_tcp.h"
#include "sock_utils.h"
#include "Tun.h"
#include "console_colors.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>


SocketTcpConnection::SocketTcpConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap,
                                         std::byte *pBuffer, int nRead)
: m_pTun(pTun), m_fdSoc(fdSoc), m_pUdpConnMap(pUdpConnMap)
{
    m_tun_ip = m_pTun->GetIPAddr();
    const int fdTun = m_pTun->GetFd();

    socks5_tcp::send_sync_ack_to_tun(fdTun, pBuffer, nRead);

    struct iphdr *iph = (struct iphdr *)pBuffer;
    const unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(pBuffer + iphdrlen);
    m_addr     = iph->daddr;
    m_raw_port = tcph->source;
}

SocketTcpConnection::~SocketTcpConnection()
{
    if (sock_utils::close_connection(m_fdSoc) == -1) {
        std::cout << RED << "ERROR: SocketTcpConnection::sock_utils::close_connection failed: ";
        std::cout << m_fdSoc << "." << RESET << std::endl;
    }
}

void SocketTcpConnection::HandleEvent()
{
    const int nRead = sock_utils::read_data(m_fdSoc, m_buffer, sizeof(m_buffer), 0);

    if (nRead == 0) {
        return; // TODO
    }
    ipv4::print_data((unsigned char *)m_buffer, nRead);
    // TODO create TCP packet (this is payload info)
    // TODO - unfinished

    const int fdTun = m_pTun->GetFd();
    socks5_tcp::send_ack_to_tun(fdTun, m_tun_ip, m_addr, m_raw_port);
    socks5_tcp::send_packet_to_tun(fdTun,
                                   m_buffer, nRead,
                                   m_tun_ip,
                                   m_addr,
                                   m_raw_port,
                                  *m_pUdpConnMap);
}
