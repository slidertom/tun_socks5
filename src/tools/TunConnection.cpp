#include "TunConnection.h"

#include "console_colors.h"
#include "socks5_tcp.h"
#include "sock_utils.h"
#include "socks5_udp.h"
#include "SocketUdpConnection.h"
#include "PollMgr.h"
#include "Tun.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>

TunConnection::TunConnection(Tun *pTun,
                  const char *sSocs5Server, uint16_t nSocs5Port,
                  PollMgr *pPollMgr, Ipv4ConnMap *pUdpConnMap)
: m_pTun(pTun), m_pPollMgr(pPollMgr), m_pUdpConnMap(pUdpConnMap),
  m_sSocs5Server(sSocs5Server), m_nSocs5Port(nSocs5Port)
{
    if ( !socks5_tcp::get_udp_bind_params(sSocs5Server, nSocs5Port, m_fdSoc, m_udpBindAddr, m_udpBindPort) ) {
        std::cout << RED << "socks5_get_udp_bind_params failed." << RESET << std::endl;
        this->m_fdSoc = -1;
        return;
    }

    std::cout << "UDP ADDRESS AND BND.PORT: \t" << ::inet_ntoa(m_udpBindAddr) << ":" << m_udpBindPort << std::endl;
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
#include <unistd.h>
void TunConnection::HandleEvent()
{
    const int nRead = m_pTun->Read((char *)m_buffer, sizeof(m_buffer));
    if (nRead <= 0) {
        return;
    }

    if ( ipv4::is_udp(m_buffer) )
    {
        std::cout << "TUN => SOC ";
        ipv4::print_udp_packet(m_buffer, nRead);

        // connections "gc"
        size_t conn_cnt = m_dest_to_socket.size();
        if (conn_cnt >= m_nMaxConnCnt) {
            auto it_first = m_conns.begin();
            {
                auto found = m_dest_to_socket.find(it_first->first);
                if (found != m_dest_to_socket.end()) {
                    m_dest_to_socket.erase(found);
                }
                m_pPollMgr->Delete(it_first->second);
            }
            {
                auto found = m_pUdpConnMap->find(it_first->first);
                if (found != m_pUdpConnMap->end()) {
                    m_pUdpConnMap->erase(found);
                }
            }
            m_conns.erase(it_first);
        }

        int fdSocUdp = -1;
        auto dest = ipv4::map_udp_packet((const std::byte *)m_buffer, nRead, *m_pUdpConnMap);
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
        socks5_udp::send_packet_to_socket(fdSocUdp, m_buffer, nRead);
    }
    else if ( ipv4::is_tcp(m_buffer) )
    {
        ipv4::print_ip_header(m_buffer, nRead);

        struct iphdr *iph = (struct iphdr *)m_buffer;
        const unsigned short iphdrlen = iph->ihl*4;
        struct tcphdr *tcph = (struct tcphdr *)(m_buffer + iphdrlen);
        const int fdTun = m_pTun->GetFd();

        static int fdSoc = -1;
        // client -> application must get 3-way handshake to retrieve exact request
        // client (fdTun) -> sync
        //      server (fdSoc) -> sync, ack
        // client (fdTun) -> ack
        // client (get)
        if (fdSoc == -1) {
            fdSoc = sock_utils::create_tcp_socket_client(m_sSocs5Server.c_str(), m_nSocs5Port);
            socks5_tcp::client_greeting_no_auth(fdSoc);

            struct sockaddr_in dest;
            ::memset(&dest, 0, sizeof(dest));
            socks5_tcp::tcp_client_connection_request(fdSoc, iph->daddr, 80);

            //socks5_tcp::server_three_way_handshake(tcph->th_sport, fdTun, nRead, (const char *)m_buffer);
            //socks5_tcp::recv_conn_req(fdTun, nRead, (char *)m_buffer);
            //socks5_tcp::send_sync_to_tun(fdTun, m_buffer, nRead);  //server (fdSoc) -> sync, ack
            socks5_tcp::send_sync_ack_to_tun(fdTun, m_buffer, nRead);
            return;
        }

        const size_t payload_size = (nRead - tcph->doff*4 - iphdrlen);
        if (payload_size == 0) { // sync, ack
            //socks5_tcp::send_sync_to_tun(fdTun, m_buffer, nRead); // do send ack
            //socks5_tcp::send_sync_ack_to_tun(fdTun, m_buffer, nRead);
            return; // ignore ack
        }

        sock_utils::write_data(fdSoc,(const std::byte *)m_buffer + iphdrlen + tcph->doff*4, payload_size, 0);

        constexpr std::size_t reply_buff_size = 65535;
        char read_buffer_reply[reply_buff_size];
        int size = sock_utils::read_data(fdSoc, (std::byte *)read_buffer_reply, reply_buff_size, 0);
        ipv4::print_ip_header((std::byte *)read_buffer_reply, reply_buff_size);

        //const int nRet = ::write(fdTun, read_buffer_reply, reply_buff_size);

        socks5_tcp::send_packet_to_tun(fdTun,
                                       m_buffer, nRead,
                                       m_pTun->GetIPAddr(),
                                       iph->daddr,
                                       tcph->th_sport,
                                       *m_pUdpConnMap);

        //sock_utils::close_connection(fdSoc);
    }
    else {

    }
}
