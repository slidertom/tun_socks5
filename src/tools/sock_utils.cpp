#include "sock_utils.h"

#include "console_colors.h"

#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void sock_utils::get_socket_info(int fdSoc, struct sockaddr_in &addr) noexcept
{
    ::memset(&addr, 0, sizeof(addr));
    socklen_t addrlen = sizeof(addr);
    ::getsockname(fdSoc,  (struct sockaddr *)&addr, &addrlen);
}

void sock_utils::print_socket_info(int fdSoc) noexcept
{
    struct sockaddr_in addr;
    sock_utils::get_socket_info(fdSoc, addr);

    char sock_ip[16];
    ::inet_ntop(AF_INET, &addr.sin_addr, sock_ip, sizeof(sock_ip));
    uint16_t scPort = ntohs(addr.sin_port);
    std::cout << "fd: " << fdSoc << "\t" << sock_ip << ":" << scPort << std::endl;
}

void sock_utils::check_socket(int fdSoc) noexcept
{
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (::getsockopt(fdSoc, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0) {
        std::cout << "getsockopt failed socket fd: " << fdSoc << std::endl;
        return;
    }

    if (error != 0) {
        std::cout << "socks5 proxy failing" << std::endl;
    }
}

int sock_utils::create_udp_socket(struct in_addr *inp, uint16_t dport) noexcept
{
    const int sock_fd = ::socket(AF_INET, SOCK_DGRAM, 0);

    // Set socket to be nonblocking.
    const int flags = ::fcntl(sock_fd, F_GETFL, 0);
    ::fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_addr   = *inp;
    addr.sin_port   = ::htons(dport);
    addr.sin_family = AF_INET;
    ::memset(addr.sin_zero, 0, 8);
    const int connect_ret = ::connect(sock_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(sockaddr));

    if (connect_ret == -1) {
        std::cout << RED << "UDP Socket connect has failed." << RESET << std::endl; // TODO: log function with levels
        return -1;
    }

    return sock_fd;
}

int sock_utils::read_data(int fdSoc, std::byte *buffer, size_t buff_read_len, int recv_flag) noexcept
{
    const int recv_ret = ::recv(fdSoc, buffer, buff_read_len, recv_flag);
    if (recv_ret < 0 ) {
        std::cout << RED << "sock_utils::read_data failed." << RESET << std::endl; // TODO: log function with levels
        return recv_ret;
    }

    return recv_ret;
}

int sock_utils::write_data(int fdSoc, const std::byte *buffer, size_t buff_write_len, int send_flags) noexcept
{
    // https://beej.us/guide/bgnet/html/#sendall
    // Remember back in the section about send(), above,
    // when I said that send() might not send all the bytes you asked it to?
    // That is, you want it to send 512 bytes, but it returns 412. What happened to the remaining 100 bytes?

    size_t total = 0;                  // how many bytes we've sent
    size_t bytesleft = buff_write_len; // how many we have left to send
    int n;
    while (total < buff_write_len) {
        n = ::send(fdSoc, buffer + total, bytesleft, 0); // MSG_NOSIGNAL?
        if (n == -1) {
            break;
        }
        total     += n;
        bytesleft -= n;
    }

    return n == -1 ? -1 : total; // return -1 on failure, number actually sent bytes on success
}

int sock_utils::close_connection(int fdSoc) noexcept
{
    const int close_ret = ::close(fdSoc);
    return close_ret;
}

int sock_utils::create_tcp_socket_client(const char *name, std::uint16_t port) noexcept
{
    hostent *hoste;
    sockaddr_in addr;
    if ((hoste = ::gethostbyname(name)) == nullptr) {
        std::cout << RED << "gethostbyname() failed." << RESET << std::endl;
        return -1;
    }
                                 // O_NONBLOCK
    const int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0 ) {
        std::cout << RED << "socket create_tcp_socket_client failed." << RESET << std::endl;
        return -2;
    }

    addr.sin_addr = *(reinterpret_cast<struct in_addr *>(hoste->h_addr));
    addr.sin_port = ::htons(port);
    addr.sin_family = AF_INET;
    ::memset(addr.sin_zero, 0, 8);
    const int connect_ret = connect(sock_fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(struct sockaddr));
    if (connect_ret < 0 ) {
        std::cout << RED << "connect create_tcp_socket_client failed." << RESET << std::endl;
        return -3;
    }

    // https://www.ibm.com/support/pages/ibm-aix-tcp-keepalive-probes
    // The option is enabled on a per-application basis by using the setsockopt() subroutine to set the socket option SO_KEEPALIVE to 1.
    // There is no option available to enable keepalive system-wide.
    // Many programs, such as telnetd, provide a way to enable or disable the TCP keepalive via command line arguments or configuration options.

    constexpr int keepalive = 1;
    ::setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

    // TCP keepalive has three timer  options:
    // TCP_KEEPIDLE: How long to wait before sending out the first probe on an idle connection
    constexpr int keepidle = 1;
    ::setsockopt(sock_fd, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    // TCP_KEEPINTVL: The frequency of keepalive packets after the first one is sent
    constexpr int keepintvl = 1;
    ::setsockopt(sock_fd, SOL_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    // TCP_KEEPCNT: The number of unanswered probes required to force closure of the socket
    constexpr int keepcnt = 8;
    ::setsockopt(sock_fd, SOL_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    return sock_fd;
}
