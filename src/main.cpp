#include <iostream>

#include "tools/Tun.h"
#include "tools/IPv4.h"
#include "tools/socks5_udp.h"
#include "tools/socks5_tcp.h"
#include "tools/Traffic2Tun.h"
#include "tools/sock_utils.h"
#include "tools/console_colors.h"
#include "tools/PollMgr.h"
#include "tools/TunConnection.h"
#include "tools/SocketUdpConnection.h"

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

	sock_utils::write_data(fdSoc, (const std::byte *)sample_request.c_str(), sample_request.size(), 0);

	constexpr std::size_t reply_buff_size = 2048;
	char read_buffer_reply[reply_buff_size];
	sock_utils::read_data(fdSoc, (std::byte *)read_buffer_reply, reply_buff_size, 0);
	std::cout << "IP addrees:"     << std::endl;
	std::cout << read_buffer_reply << std::endl;
}

template <class TTun>
static void SendSockData2(int fdSoc, TTun &tun)
{
	std::string sample_request = "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.65.2\r\n\r\n";
	sock_utils::write_data(fdSoc, (const std::byte *)sample_request.c_str(), sample_request.size(), 0);

	constexpr std::size_t reply_buff_size = 2048;
	std::byte read_buffer_reply[reply_buff_size];
	sock_utils::read_data(fdSoc, read_buffer_reply, reply_buff_size, 0);
	std::cout << read_buffer_reply << std::endl;
	tun.Write(read_buffer_reply, reply_buff_size);

}

static void SendSockTest(int fdSoc)
{
    std::string sDstAddress = "34.117.59.81";
	//SOCKS5::DNS_local_resolve("www.ipinfo.io", sDstAddress);
    int nRet = socks5_tcp::tcp_client_connection_request(fdSoc, sDstAddress.c_str(), 80); // ?
    if ( nRet == -1) {
        std::cout << "client_connection_request error" << std::endl;
    }

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

    const char *sSocs5Server = "212.122.76.241";
    //const uint16_t nSocs5Port = 1081;

    //const char *sSocs5Server = "192.168.19.142";
    const uint16_t nSocs5Port = 1082;

    Tun tun;
    const int fdTun = tun.Init("tun2sc5", "10.0.0.1");
    if (fdTun < 0) {
        std::cout << RED << "Tun interface start has failed: " << fdTun << RESET << std::endl;
        return 0;
    }

    std::cout << GREEN << "Tun interface started: " << fdTun << RESET << std::endl;
    system("echo 0 > /proc/sys/net/ipv4/conf/tun2sc5/rp_filter");

    const std::string sEthName = Traffic2Tun::GetProxyEthName(sSocs5Server);
    if ( sEthName.empty() ) {
        return 0;
    }
    std::cout << GREEN << "Default ethernet device: " << sEthName << RESET << std::endl;

    redirect_traff.Start(sSocs5Server, sEthName.c_str());

//    {  // Direct socket server test
        const int fdSoc = sock_utils::create_tcp_socket_client(sSocs5Server, nSocs5Port);
        if (fdSoc <= 0) {
            std::cout << "Socket start has failed: " << fdSoc << std::endl;
            return 0;
        }
        std::cout << "Socket has started:" << fdSoc << std::endl;
        socks5_tcp::client_greeting_no_auth(fdSoc);
        SendSockTest(fdSoc);
        sock_utils::close_connection(fdSoc);
 //   }


    std::cout << std::endl;

    PollMgr poll;
    Ipv4ConnMap udp_conn_map;

    TunConnection *pTunConn = new TunConnection(&tun, sSocs5Server, nSocs5Port, &poll, &udp_conn_map);
    if ( !pTunConn->IsValid() ) {
        delete pTunConn;
        return 0;
    }

    poll.Add(fdTun, pTunConn);
    //poll.Add(fdSoc, nullptr);

    while (!_do_exit)  {
        poll.Wait();
    }

    return 0;
}
