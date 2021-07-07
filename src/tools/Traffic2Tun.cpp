#include "Traffic2Tun.h"

#include "console_colors.h"
#include "str_util.h"

#include <iostream>

static void call_system(const char *cmd) noexcept
{
    std::cout << CYAN << "$ " << cmd << RESET << std::endl;
    ::system(cmd);
}

// https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
static std::string exec(const char *cmd) noexcept
{
    std::cout << CYAN << "$ " << cmd << RESET << std::endl;

    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        return "";
    }
    while (::fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    std::cout << WHITE << "$ " << result << RESET << std::endl;
    return result;
}

void Traffic2Tun::SetUpIpv4() noexcept
{
    // Enable ip routing. Required if NAT included
    ::call_system("echo 1 > /proc/sys/net/ipv4/ip_forward");
}

//https://gist.github.com/rsanden/ba29b8ea7d5d3bd482e717413a745243
void Traffic2Tun::Start(const char *sTunDev,
                        const char *sProxyIP, const char *sProxyDev) noexcept
{
    ::call_system("ip route flush cache");
    //call_system("iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1");
    //call_system("ip rule add fwmark 1 table 1");  // forward traffic into "virtual" table if mark 1
    ::call_system("ip rule add ipproto udp table 1");
    ::call_system("ip rule add ipproto tcp dport 80 table 1");
    ::call_system(::FormatStr("ip route add default dev %s table 1", sTunDev).c_str());
    const std::string sRouteProxytoEth  = ::FormatStr("ip route add %s/32  dev %s table 1", sProxyIP, sProxyDev);
    ::call_system(sRouteProxytoEth.c_str());
}

void Traffic2Tun::CleanUp() noexcept
{
    //call_system("ptables -t mangle -D OUTPUT -p udp -j MARK --set-mark 1 2>/dev/null");
    //::call_system("ip rule del fwmark 1 table 1 2>/dev/null");
    ::call_system("ip rule del ipproto udp table 1 2>/dev/null");
    ::call_system("ip route flush table 1");
    ::call_system("ip route flush cache");
}

std::string Traffic2Tun::GetProxyEthName(const char *sProxyIp) noexcept
{
    const std::string sCmd = ::FormatStr("ip route get %s", sProxyIp);

    const std::string sOutput = ::exec(sCmd.c_str());
    std::vector<std::string> result;
    ::str_split_string(sOutput.c_str(), " ", result, false);

    bool bFound = false;
    for (const std::string &str : result)
    {
        if (bFound) {
            return str;
        }

        if (str == "dev") {
            bFound = true;
        }
    }

    std::cerr << RED << "Ethernet device was not found. Output: '" << sOutput << "'" <<  RESET << std::endl;
    return "";
}
