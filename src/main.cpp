#include <iostream>

#include "tools/Tun.h"
#include "tools/IPv4.h"
#include "tools/socks5_tcp.h"
#include "tools/Traffic2Tun.h"
#include "tools/sock_utils.h"
#include "tools/console_colors.h"
#include "tools/PollMgr.h"
#include "tools/TunConnection.h"
#include "tools/str_util.h"

// netcat -u <host> <port>
// netcat -u 8.8.8.8 53
static void SendGetProxyIP(int fdSoc)
{
	const std::string sample_request = "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.65.2\r\n\r\n";
	sock_utils::write_data(fdSoc, (const std::byte *)sample_request.c_str(), sample_request.size(), 0);

	constexpr std::size_t reply_buff_size = 2048;
	char read_buffer_reply[reply_buff_size];
	sock_utils::read_data(fdSoc, (std::byte *)read_buffer_reply, reply_buff_size, 0);
	std::cout << "IP addrees:"     << std::endl;
	std::cout << read_buffer_reply << std::endl;
}

static void SendSockTest(int fdSoc)
{
    std::string sDstAddress = "34.117.59.81";
    const int nRet = socks5_tcp::tcp_client_connection_request(fdSoc, sDstAddress.c_str(), 80); // ?
    if ( nRet == -1) {
        std::cout << "client_connection_request error" << std::endl;
    }
    SendGetProxyIP(fdSoc);
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

static inline std::pair<std::string, uint16_t> GetParams(int argc, char *argv[])
{
    if (argc == 0) {
        return std::make_pair("", 0);
    }

    if (argc > 2) {
        std:: cout << argv[1] << " " << argv[2] << std::endl;
        const int port = std::atoi(argv[2]);
        return std::make_pair(argv[1], port);
    }

    if (argc == 2) {
        std::vector<std::string> result;
        ::str_split_string(argv[1], ":", result, false);
        if (result.size() == 2) {
            const int port = std::atoi(result[1].c_str());
            return std::make_pair(result[0], port);
        }
    }

    return std::make_pair("", 0);
}

int main(int argc, char * argv[])
{
    auto params = GetParams(argc, argv);
    if (params.second == 0) {
        std::cout << "Expected params sample:" << std::endl;
        std::cout << "$ tunproxy 10.10.10.10 1080" << std::endl;
        std::cout << "or" << std::endl;
        std::cout << "$ tunproxy 10.10.10.10:1080" << std::endl;
        return 0;
    }

    Traffic2Tun::SetUpIpv4();

    Traffic2Tun redirect_traff;
    redirect_traff.CleanUp();

    // https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
    set_signal(SIGINT,  sigexit);
    set_signal(SIGQUIT, sigexit);
    set_signal(SIGTERM, sigexit);
    set_signal(SIGHUP,  sigexit);

    const char *sTunIp  = "10.0.0.1";
    const char *sTunDev = "tun2sc5";

    const char *sSocs5Server  = params.first.c_str();
    const uint16_t nSocs5Port = params.second;

    Tun tun;
    const int fdTun = tun.Init(sTunDev, sTunIp);
    if (fdTun < 0) {
        std::cout << RED << "Tun interface start has failed: " << fdTun << RESET << std::endl;
        return 0;
    }

    std::cout << GREEN << "Tun interface started: " << fdTun << RESET << std::endl;
    system("echo 0 > /proc/sys/net/ipv4/conf/tun2sc5/rp_filter");
    //echo "3" > /proc/sys/net/ipv4/tcp_fastopen

    const std::string sEthName = Traffic2Tun::GetProxyEthName(sSocs5Server);
    if ( sEthName.empty() ) {
        return 0;
    }
    std::cout << GREEN << "Default ethernet device: " << sEthName << RESET << std::endl;

    redirect_traff.Start(sTunDev, sSocs5Server, sEthName.c_str());

    {  // Direct socket server test
        const int fdSoc = sock_utils::create_tcp_socket_client(sSocs5Server, nSocs5Port);
        if (fdSoc <= 0) {
            std::cout << "Socket start has failed: " << fdSoc << std::endl;
            return 0;
        }
        std::cout << "Socket has started: " << fdSoc << std::endl;
        socks5_tcp::client_greeting_no_auth(fdSoc);
        SendSockTest(fdSoc);
        sock_utils::close_connection(fdSoc);
    }

    std::cout << std::endl;

    PollMgr poll;
    Ipv4ConnMap udp_conn_map;

    TunConnection *pTunConn = new TunConnection(&tun, sSocs5Server, nSocs5Port, &poll, &udp_conn_map);
    if ( !pTunConn->IsValid() ) {
        delete pTunConn;
        return 0;
    }

    poll.Add(fdTun, pTunConn);

    while (!_do_exit)  {
        poll.Wait();
    }

    return 0;
}
