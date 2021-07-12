#pragma once

#include "Connection.h"
#include "IPv4.h"

class Tun;

class SocketUdpConnection final : public Connection
{
public:
    SocketUdpConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap);
    virtual ~SocketUdpConnection();

public:
    virtual void HandleEvent() override final;
    virtual bool SendPacket(const std::byte *buffer, size_t size);

private:
    Tun *m_pTun {nullptr};
    int m_fdSoc {-1};
    uint32_t m_tun_ip {0};
    Ipv4ConnMap *m_pUdpConnMap {nullptr};

private:
    SocketUdpConnection(SocketUdpConnection &&x) = delete;
    SocketUdpConnection(const SocketUdpConnection &x) = delete;
    SocketUdpConnection &operator=(SocketUdpConnection &&x) = delete;
    SocketUdpConnection &operator=(const SocketUdpConnection &x) = delete;
};
