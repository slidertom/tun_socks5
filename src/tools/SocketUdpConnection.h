#pragma once

#include "Connection.h"
#include "IPv4.h"

class Tun;

class SocketUdpConnection final : public Connection
{
public:
    SocketUdpConnection(Tun *pTun, int fdSoc, Ipv4ConnMap *pUdpConnMap);
    virtual ~SocketUdpConnection() { }

public:
    virtual void HandleEvent() override final;

private:
    int m_fdSoc;
    Tun *m_pTun;
    uint32_t m_tun_ip;
    Ipv4ConnMap *m_pUdpConnMap;

private:
    SocketUdpConnection(SocketUdpConnection &&x) = delete;
    SocketUdpConnection(const SocketUdpConnection &x) = delete;
    SocketUdpConnection &operator=(SocketUdpConnection &&x) = delete;
    SocketUdpConnection &operator=(const SocketUdpConnection &x) = delete;
};
