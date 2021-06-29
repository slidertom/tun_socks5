#pragma once

#include <string>

class Traffic2Tun final
{
public:
    Traffic2Tun() {
        // Do start with manual call -> Start();
    }

    ~Traffic2Tun() {
        CleanUp();
    }

// Static operations
public:
    static void SetUpIpv4() noexcept;

    static std::string GetProxyEthName(const char *sProxyIp) noexcept;

    static void CleanUp() noexcept;
    static void Start(const char *sTunDev,
                      const char *sProxyIP, const char *sProxyDev) noexcept;
};
