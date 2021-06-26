#pragma once

#include <bits/stdc++.h>

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

private:
    Tun *m_pTun;

    int m_fdSoc    {0}; // UDP associated socket
    int m_fdSocUdp {0}; // TCP authorization socket

    // TODO: tcp sockets map by destination

    PollMgr *m_pPollMgr;
    Ipv4ConnMap *m_pUdpConnMap;

private:
    TunConnection(const TunConnection &x) = delete;
    TunConnection(TunConnection &&x) = delete;
    TunConnection &operator=(const TunConnection &x) = delete;
    TunConnection &operator=(TunConnection &&x) = delete;
};
