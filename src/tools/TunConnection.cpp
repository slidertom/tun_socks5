#include "TunConnection.h"

#include "console_colors.h"
#include "socks5_tcp.h"
#include "sock_utils.h"
#include "socks5_udp.h"
#include "SocketUdpConnection.h"
#include "PollMgr.h"
#include "Tun.h"

#include <arpa/inet.h>

TunConnection::TunConnection(Tun *pTun,
                  const char *sSocs5Server, uint16_t nSocs5Port,
                  PollMgr *pPollMgr, Ipv4ConnMap *pUdpConnMap)
: m_pTun(pTun), m_pPollMgr(pPollMgr), m_pUdpConnMap(pUdpConnMap)
{
    if ( !socks5_tcp::get_udp_bind_params(sSocs5Server, nSocs5Port, m_fdSoc, m_udpBindAddr, m_udpBindPort) ) {
        std::cout << RED << "socks5_get_udp_bind_params failed." << RESET << std::endl;
        this->m_fdSoc = -1;
        return;
    }

    std::cout << "UDP ADDRESS AND BND.PORT: \t" << inet_ntoa(m_udpBindAddr) << ":" << m_udpBindPort << std::endl;
    std::cout << "Max parallel udp sockets count: " << m_nMaxConnCnt << std::endl;
}

TunConnection::~TunConnection()
{
    for (const auto &elem : m_dest_to_socket) {
        if (sock_utils::close_connection(elem.second) == -1) {
            std::cout << RED << "ERROR: sock_utils::close_connection failed: ";
            std::cout << elem.second << "." << RESET << std::endl;
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
    const int nRead = m_pTun->Read((char *)m_buffer, sizeof(m_buffer));
    if (nRead <= 0) {
        return;
    }

    if ( ipv4::is_udp((const std::byte *)m_buffer) )
    {
        std::cout << "TUN => SOC ";
        ipv4::print_udp_packet((const std::byte *)m_buffer, nRead);

        // connections "gc"
        size_t conn_cnt = m_dest_to_socket.size();
        if ( conn_cnt >= m_nMaxConnCnt) {
            auto it_first = m_conns.begin();
            {
                auto found = m_dest_to_socket.find(it_first->first);
                if (found != m_dest_to_socket.end()) {
                    m_dest_to_socket.erase(found);
                }
                m_pPollMgr->Delete(it_first->second);
                m_conns.erase(it_first);
            }
            {
                auto found = m_pUdpConnMap->find(it_first->first);
                if (found != m_pUdpConnMap->end()) {
                    m_pUdpConnMap->erase(found);
                }
            }
        }

        int fdSocUdp = -1;
        auto dest = ::map_udp_packet((const std::byte *)m_buffer, nRead, *m_pUdpConnMap);
        auto found = m_dest_to_socket.find(dest);
        if (found != m_dest_to_socket.end()) {
            fdSocUdp = found->second;
        }
        else {
            fdSocUdp = sock_utils::create_udp_socket(&m_udpBindAddr, m_udpBindPort);
            m_pPollMgr->Add(fdSocUdp, new SocketUdpConnection(m_pTun, fdSocUdp, m_pUdpConnMap));
            m_dest_to_socket[dest] = fdSocUdp;
            m_conns.push_back(std::make_pair(dest, fdSocUdp));

            std::cout << YELLOW << "UDP Socket: ";
            sock_utils::print_socket_info(fdSocUdp);
            std::cout << RESET;
        }

        socks5_udp::send_packet_to_socket(fdSocUdp, (const std::byte *)m_buffer, nRead);
    }
    else {
        // TODO: get TCP payload
        // get port and destination
        // const int fdSoc = sock_utils::create_tcp_socket_client(sSocs5Server, nSocs5Port);
        // socks5_tcp::client_greeting_no_auth(fdSoc);
        // socks5_tcp::tcp_client_connection_request
        // send payload
    }
}
