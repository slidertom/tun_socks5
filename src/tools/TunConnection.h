#pragma once

#include <bits/stdc++.h>
#include <arpa/inet.h>

#include "Connection.h"
#include "IPv4.h"

class Tun;
class PollMgr;

class TunConnection final : public Connection
{
public:
    TunConnection(Tun *pTun,
                  const char *sSocs5Server, uint16_t nSocs5Port,
                  PollMgr *pPollMgr, Ipv4ConnMap *pUdpConnMap);
    virtual ~TunConnection();

public:
    virtual void HandleEvent() override final;

public:
    bool IsValid() const noexcept { return this->m_fdSoc != -1; }

private:
    Tun *m_pTun {nullptr};

    int m_fdSoc    {-1}; // TCP authorization socket
    int m_fdSocUdp {-1}; // UDP associated socket

    struct in_addr m_udpBindAddr;
    uint16_t       m_udpBindPort;

    PollMgr *m_pPollMgr {nullptr};
    Ipv4ConnMap *m_pUdpConnMap {nullptr};
    std::map<addr_ipv4, int> m_dest_to_socket;

private:
    TunConnection(const TunConnection &x) = delete;
    TunConnection(TunConnection &&x) = delete;
    TunConnection &operator=(const TunConnection &x) = delete;
    TunConnection &operator=(TunConnection &&x) = delete;
};
