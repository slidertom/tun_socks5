#include <iostream>

#include "tools/Tun.h"
#include "tools/IPv4.h"
#include "tools/socks5_udp.h"
#include "tools/socks5_tcp.h"
#include "tools/Traffic2Tun.h"
#include "tools/sock_utils.h"
#include "tools/console_colors.h"

// etc/resolv.con change dns server from local

#include "stdlib.h"

// intro: https://backreference.org/2010/03/26/tuntap-interface-tutorial/
// continue: https://github.com/LaKabane/libtuntap (reused only Linux based impl.)

// https://github.com/txthinking/socks5 ?
// https://github.com/wtdcode/tun2socks does everything
// https://github.com/ambrop72/badvpn does everything

// https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ip__udp/socket.html
// https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ip__tcp/socket.html

// TODO:
// udp-generator => iperf
// sever: iperf3 -s
// iperf3 -u -c client.ip.address -b 1M

// glider
// https://github.com/nadoo/glider/releases/download/v0.14.0/glider_0.14.0_linux_amd64.tar.gz
//  ./glider -verbose -listen socks5://:1082

//   Use non-blocking IO.

// ssh -N -D 0.0.0.0:1080 localhost
// DOES NOT WORK with UDP!!!!
// constexpr usage

// There is a trick: one must open a normal socket (UDP in this case) and use the ioctl syscall with this socket-file-descriptor
// and not with the file-descriptor of the TAP-Device but with the ifreq-variable of the TAP-Device.
// After finish the configuration of the TAP-Device the socket can closed. This trick should be a little bit more highlighted
// in the description, in my first reading of the source code i do not have seen it.

/* local_ip4 is in network byte address order.*/

static void SendSockData(int fdSoc)
{
	std::string sample_request = "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.65.2\r\n\r\n";
	//pSocket->write_proxy(sample_request.size(), sample_request.c_str());
	sock_utils::write_data(fdSoc, sample_request.c_str(), sample_request.size(), 0);

	constexpr std::size_t reply_buff_size = 2048;
	char read_buffer_reply[reply_buff_size];
	int nRet = sock_utils::read_data(fdSoc, read_buffer_reply, reply_buff_size, 0);
	nRet;
	std::cout << "IP addrees:"     << std::endl;
	std::cout << read_buffer_reply << std::endl;
}

template <class TTun>
static void SendSockData2(int fdSoc, TTun &tun)
{
	std::string sample_request = "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.65.2\r\n\r\n";
	sock_utils::write_data(fdSoc, sample_request.c_str(), sample_request.size(), 0);

	constexpr std::size_t reply_buff_size = 2048;
	char read_buffer_reply[reply_buff_size];
	sock_utils::read_data(fdSoc, read_buffer_reply, reply_buff_size, 0);
	std::cout << read_buffer_reply << std::endl;
	tun.Write(read_buffer_reply, reply_buff_size);

}

static void SendSockTest(int fdSoc)
{
    std::string sDstAddress = "34.117.59.81";
	//SOCKS5::DNS_local_resolve("www.ipinfo.io", sDstAddress);
    int nRet = socks5_tcp_client_connection_request(fdSoc, sDstAddress.c_str(), 80); // ?
    if ( nRet == -1) {
        std::cout << "client_connection_request error" << std::endl;
    }
    /*
    // accepted only one time by server
    client_greeting_no_auth(fdSoc);
    nRet = SOCKS5_Common::client_connection_request(fdSoc, sDstAddress.c_str(), 80); // ?
    if ( nRet == -1) {
        std::cout << "client_connection_request error" << std::endl;
    }
    */
    SendSockData(fdSoc);
}

static int  _do_exit = 0;
static void sigexit(int signo)
{
    _do_exit = 1;
}

static void set_signal(int signo, void (*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = (void (*)(int))handler;
    sigaction(signo, &sa, NULL);
}

#include <sys/epoll.h>
#include "tools/Connection.h"

// https://www.ulduzsoft.com/2014/01/select-poll-epoll-practical-difference-for-system-architects/
class PollMgr
{
public:
    PollMgr()
    {
        // Create the epoll descriptor. Only one is needed per app, and is used to monitor all sockets.
        // The function argument is ignored (it was not before, but now it is), so put your favorite number here
        m_fdPoll = epoll_create(0xCAFE);
    }

    ~PollMgr()
    {
        if (m_fdPoll >= 0) {
            ::close(m_fdPoll);
        }
    }

// Operations
public:
    bool Add(int fd, Connection *pConn) noexcept
    {
        // Initialize the epoll structure in case more members are added in future
        struct epoll_event ev {0};

        // https://man7.org/linux/man-pages/man2/epoll_ctl.2.html
        // EPOLLIN - read
        // EPOLLRDHUP  - Stream socket peer closed connection, or shut down writing
        // half of connection.  (This flag is especially useful for
        // writing simple code to detect peer shutdown when using
        // edge-triggered monitoring.)
        ev.events  = EPOLLIN|EPOLLRDHUP|EPOLLERR;
        ev.data.fd = fd;
        // Associate the connection class instance with the event. You can associate anything
        // you want, epoll does not use this information. We store a connection class pointer, pConnection1
        ev.data.ptr = pConn ? pConn : nullptr;

        const int res = epoll_ctl(m_fdPoll, EPOLL_CTL_ADD, fd, &ev);

        if (res == EEXIST) {
            return false; // please fix code logic
        }

        if (res < 0) {
            return false;
        }

        return true;
    }

    void Wait() const noexcept
    {
        constexpr int maxevents = 4;
        constexpr int timeout   = -1;
        struct epoll_event events[maxevents];
        const int ret = epoll_wait(m_fdPoll, events, maxevents, timeout);
        for (int i1 = 0; i1 < ret; ++i1) {
            if (events[i1].data.ptr) {
                Connection *pConn = (Connection *)events[i1].data.ptr;
                pConn->HandleEvent();
            }

        }
    }

// Attributes
private:
    int m_fdPoll;

private:
    PollMgr(PollMgr &&x) = delete;
    PollMgr(const PollMgr &x) = delete;
    PollMgr &operator=(PollMgr &&x) = delete;
    PollMgr &operator=(const PollMgr &x) = delete;
};

class SocketConnection : public Connection
{
public:
    SocketConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap)
        : m_pTun(pTun), m_fdSoc(fdSoc), m_pUdpConnMap(pUdpConnMap)
    {
         ::inet_pton(AF_INET, "10.0.0.1", &m_tun_ip);
    }
    virtual ~SocketConnection() { }

public:
    virtual void HandleEvent() override
    {
        const int nRead = sock_utils::read_data(m_fdSoc, m_buffer, sizeof(m_buffer), 0);
        if ( nRead > 0 ) {
            //m_pTun->Write(m_buffer, nRead);
            const int fdTun = m_pTun->GetFd();
            ::socks5_send_udp_packet_to_tun(fdTun, (unsigned char *)m_buffer, nRead,
                                            m_tun_ip, *m_pUdpConnMap);
        }
        else {
            std::cout << "Socket closed connection: " << m_fdSoc << std::endl;
        }
    }

private:
    int m_fdSoc;
    Tun *m_pTun;
    uint32_t m_tun_ip;
    Ipv4ConnMap *m_pUdpConnMap;

private:
    SocketConnection(SocketConnection &&x) = delete;
    SocketConnection(const SocketConnection &x) = delete;
    SocketConnection &operator=(SocketConnection &&x) = delete;
    SocketConnection &operator=(const SocketConnection &x) = delete;
};

class TunConnection : public Connection
{
public:
    TunConnection(Tun *pTun,
                  const char *sSocs5Server, uint16_t nSocs5Port,
                  PollMgr *pPollMgr, Ipv4ConnMap *pUdpConnMap)
        : m_pTun(pTun), m_pPollMgr(pPollMgr), m_pUdpConnMap(pUdpConnMap)
    {
        struct in_addr udpBindAddr;
        uint16_t       udpBindPort;
        if ( !::socks5_get_udp_bind_params(sSocs5Server, nSocs5Port, m_fdSoc, udpBindAddr, udpBindPort) ) {
            std::cout << RED << "socks5_get_udp_bind_params failed." << RESET << std::endl;
            exit(EXIT_FAILURE); // TODO: exception or state check
        }

        //m_pPollMgr->Add(m_fdSoc, new SocketConnection(m_pTun, m_fdSoc, m_pUdpConnMap));

        std::cout << "UDP ADDRESS AND BND.PORT: \t" << inet_ntoa(udpBindAddr) << ":" << udpBindPort << std::endl;
        m_fdSocUdp = sock_utils::create_udp_socket(&udpBindAddr, udpBindPort);
        if (m_fdSocUdp == -1) {
            std::cout << RED << "sock_utils::create_udp_socket failed." << RESET << std::endl;
            exit(EXIT_FAILURE); // TODO: exception or state check
        }

        std::cout << YELLOW << "UDP Socket: ";
        sock_utils::print_socket_info(m_fdSocUdp);
        std::cout << RESET;

        m_pPollMgr->Add(m_fdSocUdp, new SocketConnection(m_pTun, m_fdSocUdp, m_pUdpConnMap));
    }

    virtual ~TunConnection()
    {
        if (sock_utils::close_connection(this->m_fdSocUdp) == -1) {
            std::cout << RED << "ERROR: sock_utils::close_connection failed: ";
            std::cout << this->m_fdSocUdp << "." << RESET << std::endl;
        }

        if (sock_utils::close_connection(this->m_fdSoc) == -1) {
            std::cout << RED << "ERROR: sock_utils::close_connection failed: ";
            std::cout << this->m_fdSoc << "." << RESET << std::endl;
        }
    }

public:
    virtual void HandleEvent() override
    {
        const int nRead = m_pTun->Read(m_buffer, sizeof(m_buffer));
        if (nRead <= 0) {
            return;
        }

        if ( ipv4::is_udp(m_buffer) ) {
            std::cout << "TUN => SOC ";
            ipv4::print_udp_packet((unsigned char *)m_buffer, nRead);
            ::map_udp_packet(m_buffer, nRead, *m_pUdpConnMap);
            ::socks5_send_udp_packet(m_fdSocUdp, (unsigned char *)m_buffer, nRead);
        }
        else {
            //sendData(fdSoc, m_buffer, nRead);
        }
    }

private:
    Tun *m_pTun;

    int m_fdSoc {0}; // UDP associate socket

    int m_fdSocUdp {0};
    PollMgr *m_pPollMgr;
    Ipv4ConnMap *m_pUdpConnMap;
};

int main()
{
    Traffic2Tun::SetUpIpv4();

    Traffic2Tun redirect_traff;
    redirect_traff.CleanUp();

    // https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
    set_signal(SIGINT,  sigexit);
    set_signal(SIGQUIT, sigexit);
    set_signal(SIGTERM, sigexit);
    set_signal(SIGHUP,  sigexit);

    //const char *sSocs5Server = "212.122.76.241";
    //const uint16_t nSocs5Port = 1081;

    const char *sSocs5Server = "192.168.19.142";
    const uint16_t nSocs5Port = 1082;

    constexpr int32_t c_nBufferSize = 2000; // for tun/tap must be >= 1500
    char buffer[c_nBufferSize]; // mtu?

    Tun tun;
    const int fdTun = tun.Init("tun2sc5", "10.0.0.1");
    if (fdTun < 0) {
        std::cout << RED << "Tun interface start has failed: " << fdTun << RESET << std::endl;
        return 0;
    }

    std::cout << BOLDMAGENTA << "Tun interface started: " << fdTun << RESET << std::endl;
    system("echo 0 > /proc/sys/net/ipv4/conf/tun2sc5/rp_filter");

    redirect_traff.Start(sSocs5Server);

//    {  // Direct socket server test
        const int fdSoc = sock_utils::create_tcp_socket_client(sSocs5Server, nSocs5Port);
        if (fdSoc == 0) {
            std::cout << "Socket start has failed: " << fdSoc << std::endl;
            return 0;
        }
        std::cout << "Socket has started:" << fdSoc << std::endl;
        socks5_client_greeting_no_auth(fdSoc);
        SendSockTest(fdSoc);
   //     SOCKS5::close_connection(fdSoc);
 //   }


    std::cout << std::endl;

    PollMgr poll;
    Ipv4ConnMap udp_conn_map;

    poll.Add(fdTun, new TunConnection(&tun, sSocs5Server, nSocs5Port, &poll, &udp_conn_map));
    poll.Add(fdSoc, nullptr);

    while (!_do_exit)  {
        poll.Wait();
    }

    return 0;
}
