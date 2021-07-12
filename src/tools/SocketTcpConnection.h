#pragma once

#include "Connection.h"
#include "IPv4.h"

class Tun;

class SocketTcpConnection final : public Connection
{
public:
    SocketTcpConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap,
                        std::byte *pBuffer, int nRead);
    virtual ~SocketTcpConnection();

public:
    virtual void HandleEvent() override final;

private:
    Tun *m_pTun {nullptr};
    int m_fdSoc {-1};
    uint32_t m_tun_ip {0};
    Ipv4ConnMap *m_pUdpConnMap {nullptr};

    uint16_t m_raw_port; // source
    uint32_t m_addr; // target

private:
    SocketTcpConnection(SocketTcpConnection &&x) = delete;
    SocketTcpConnection(const SocketTcpConnection &x) = delete;
    SocketTcpConnection &operator=(SocketTcpConnection &&x) = delete;
    SocketTcpConnection &operator=(const SocketTcpConnection &x) = delete;
};


