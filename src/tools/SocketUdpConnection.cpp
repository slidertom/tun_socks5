#include "SocketUdpConnection.h"

#include "sock_utils.h"
#include "Tun.h"
#include "socks5_udp.h"

#include <arpa/inet.h>

SocketUdpConnection::SocketUdpConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap)
: m_pTun(pTun), m_fdSoc(fdSoc), m_pUdpConnMap(pUdpConnMap)
{
     ::inet_pton(AF_INET, "10.0.0.1", &m_tun_ip); // TODO
}

void SocketUdpConnection::HandleEvent()
{
    const int nRead = sock_utils::read_data(m_fdSoc, m_buffer, sizeof(m_buffer), 0);
    if ( nRead > 0 ) {
        //m_pTun->Write(m_buffer, nRead);
        const int fdTun = m_pTun->GetFd();
        socks5_udp::send_packet_to_tun(fdTun, (unsigned char *)m_buffer, nRead,
                                        m_tun_ip, *m_pUdpConnMap);
    }
    else {
        std::cout << "Socket closed connection: " << m_fdSoc << std::endl;
    }
}
