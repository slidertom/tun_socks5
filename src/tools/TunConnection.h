#pragma once

#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <list>

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

    int m_fdSoc {-1}; // TCP authorization socket

    struct in_addr m_udpBindAddr;
    uint16_t       m_udpBindPort;

    PollMgr *m_pPollMgr {nullptr};
    Ipv4ConnMap *m_pUdpConnMap {nullptr}; // destination to source
    // destination to socket (TODO: merge with Ipv4ConnMap extension? => std::tuple/pair)
    std::unordered_map<struct addr_ipv4, int, struct addr_ipv4_hash> m_dest_to_socket;
    std::list<std::pair<struct addr_ipv4, int>> m_conns; // manage sockets order, THIS IS NOT CORRECT! ACCESS TIME required and sort!!!

    // duplicaction, complete refactoring required
    std::unordered_map<struct addr_ipv4, int, struct addr_ipv4_hash> m_dest_to_tcp_socket;

    uint32_t m_nMaxConnCnt {32};

    std::string m_sSocs5Server; // required for TCP connections
    uint16_t m_nSocs5Port;      // required for TCP connections

private:
    void ConnGC();

private:
    TunConnection(const TunConnection &x) = delete;
    TunConnection(TunConnection &&x) = delete;
    TunConnection &operator=(const TunConnection &x) = delete;
    TunConnection &operator=(TunConnection &&x) = delete;
};
