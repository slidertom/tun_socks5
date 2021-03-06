#include "SocketUdpConnection.h"

#include "sock_utils.h"
#include "Tun.h"
#include "socks5_udp.h"
#include "console_colors.h"

SocketUdpConnection::SocketUdpConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap)
: m_pTun(pTun), m_fdSoc(fdSoc), m_pUdpConnMap(pUdpConnMap)
{
    m_tun_ip = m_pTun->GetIPAddr();
}

SocketUdpConnection::~SocketUdpConnection()
{
    if (sock_utils::close_connection(m_fdSoc) == -1) {
        std::cout << RED << "ERROR: SocketUdpConnection::sock_utils::close_connection failed: ";
        std::cout << m_fdSoc << "." << RESET << std::endl;
    }
}

void SocketUdpConnection::HandleEvent()
{
    const int nRead = sock_utils::read_data(m_fdSoc, m_buffer, sizeof(m_buffer), 0);
    if ( nRead > 0 ) {
        const int fdTun = m_pTun->GetFd();
        socks5_udp::send_packet_to_tun(fdTun, (const std::byte *)m_buffer, nRead,
                                        m_tun_ip, *m_pUdpConnMap);
    }
    else {
        std::cout << "Socket closed connection: " << m_fdSoc << std::endl;
    }
}

bool SocketUdpConnection::SendPacket(const std::byte *buffer, size_t size)
{
    return socks5_udp::send_packet_to_socket(m_fdSoc, buffer, size);
}
