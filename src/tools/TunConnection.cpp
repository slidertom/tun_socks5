#include "TunConnection.h"

#include "SocketUdpConnection.h"
#include "socks5_tcp.h"
#include "sock_utils.h"
#include "PollMgr.h"
#include "Tun.h"
#include "socks5_udp.h"

#include "console_colors.h"

#include <arpa/inet.h>

TunConnection::TunConnection(Tun *pTun,
                  const char *sSocs5Server, uint16_t nSocs5Port,
                  PollMgr *pPollMgr, Ipv4ConnMap *pUdpConnMap)
: m_pTun(pTun), m_pPollMgr(pPollMgr), m_pUdpConnMap(pUdpConnMap)
{
    struct in_addr udpBindAddr;
    uint16_t       udpBindPort;
    if ( !socks5_tcp::get_udp_bind_params(sSocs5Server, nSocs5Port, m_fdSoc, udpBindAddr, udpBindPort) ) {
        std::cout << RED << "socks5_get_udp_bind_params failed." << RESET << std::endl;
        this->m_fdSoc = -1;
        return;
    }

    //m_pPollMgr->Add(m_fdSoc, new SocketConnection(m_pTun, m_fdSoc, m_pUdpConnMap));

    std::cout << "UDP ADDRESS AND BND.PORT: \t" << inet_ntoa(udpBindAddr) << ":" << udpBindPort << std::endl;
    m_fdSocUdp = sock_utils::create_udp_socket(&udpBindAddr, udpBindPort);
    if (m_fdSocUdp == -1) {
        std::cout << RED << "sock_utils::create_udp_socket failed." << RESET << std::endl;
        this->m_fdSoc = -1;
        return;
    }

    std::cout << YELLOW << "UDP Socket: ";
    sock_utils::print_socket_info(m_fdSocUdp);
    std::cout << RESET;

    m_pPollMgr->Add(m_fdSocUdp, new SocketUdpConnection(m_pTun, m_fdSocUdp, m_pUdpConnMap));
}

TunConnection::~TunConnection()
{
    if (this->m_fdSocUdp != -1) {
        if (sock_utils::close_connection(this->m_fdSocUdp) == -1) {
            std::cout << RED << "ERROR: sock_utils::close_connection failed: ";
            std::cout << this->m_fdSocUdp << "." << RESET << std::endl;
        }
    }

    if (this->m_fdSoc != -1) {
        if (sock_utils::close_connection(this->m_fdSoc) == -1) {
            std::cout << RED << "ERROR: sock_utils::close_connection failed: ";
            std::cout << this->m_fdSoc << "." << RESET << std::endl;
        }
    }
}

void TunConnection::HandleEvent()
{
    const int nRead = m_pTun->Read(m_buffer, sizeof(m_buffer));
    if (nRead <= 0) {
        return;
    }

    if ( ipv4::is_udp(m_buffer) ) {
        std::cout << "TUN => SOC ";
        ipv4::print_udp_packet((unsigned char *)m_buffer, nRead);
        ::map_udp_packet(m_buffer, nRead, *m_pUdpConnMap);
        socks5_udp::send_packet_to_socket(m_fdSocUdp, (unsigned char *)m_buffer, nRead);
    }
    else {
        //sendData(fdSoc, m_buffer, nRead);
    }
}
