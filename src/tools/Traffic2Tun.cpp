#include "Traffic2Tun.h"

#include <iostream>
#include "console_colors.h"

static void call_system(const char *command)
{
    std::cout << CYAN << "$ " << command << RESET << std::endl;
    system(command);
}

void Traffic2Tun::SetUpIpv4()
{
    // Enable ip routing. Required if NAT included
    call_system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    //execv(str_format("echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter", sTunName1).c_str());

    // Disable routing trianguliation
    // Respond to queries out the same interface, not another.
    // Helps to maintain state
    // Also protects against IP spoofing
    // TODO: replace default with tun interface name!
    //call_system("echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter");

    // Enable these additional items if required,
    // but in general this is must be defined by adminstrator
    // and it musn't be a part of this application.
    /*
    // Turn on protection from Denial of Service (DOS)
    call_system("echo 1 > /proc/sys/net/ipv4/tcp_syncookies");

    // Enable responding to ping broadcasts for the icq and msn
    call_system("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");
    // changed original 1(disable)

    // Disable acceptance of ICMP redirects
    call_system("echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects");

    // Disable source routed packets
    call_system("echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route");

    // Enable logging of packets with malformed IP addresses
    call_system("echo 1 > /proc/sys/net/ipv4/conf/all/log_martians");

    // Ignore bogus ICMP errors
    call_system("echo  1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses");

    // disable redirects
    call_system("echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects");
    */
}

//https://gist.github.com/rsanden/ba29b8ea7d5d3bd482e717413a745243
void Traffic2Tun::Start(const char *sProxyIP)
{
    call_system("ip route flush cache");

    //call_system("iptables -t mangle -A OUTPUT -d 192.168.19.138/32 -j RETURN");

    //call_system("iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1");
    //call_system("ip rule add fwmark 1 table 1");  // forward traffic into "virtual" table if mark 1

    call_system("ip rule add ipproto udp table 1");

    call_system("ip route add default dev tun2sc5 table 1");
    std::string sRouteProxytoEth  = "ip route add ";
                sRouteProxytoEth += sProxyIP;
                sRouteProxytoEth += "/32  dev ens33 table 1";
    call_system(sRouteProxytoEth.c_str());
}

/*
# 203.0.113.12 – the external IP
# 1080/tcp - Dante TCP port
# 40000:45000 – Dante UDP portrange
*/

void Traffic2Tun::CleanUp()
{
    call_system("iptables -t nat -F>/dev/null"); // TODO: delete this one
    call_system("iptables -t mangle -F>/dev/null"); // TODO: delete this one

    call_system("iptables -t nat -D POSTROUTING -o ens33   -j MASQUERADE 2>/dev/null");
    call_system("iptables -t nat -D POSTROUTING -o tun2sc5 -j MASQUERADE 2>/dev/null");
    // Allow return traffic
    call_system("iptables -D INPUT -i ens33   -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");
    call_system("iptables -D INPUT -i tun2sc5 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");
    // Forward everything
    call_system("iptables -D FORWARD -j ACCEPT 2>/dev/null");

    call_system("iptables -t nat -D POSTROUTING -m mark --mark 1 -j SNAT --to-source 10.0.0.1 2>/dev/null");
    //call_system("iptables -t mangle -D OUTPUT -p udp -j MARK --set-mark 1 2>/dev/null");
    /*
    call_system("iptables -t nat -D POSTROUTING -m mark --mark 1 -j SNAT --to-source 10.0.0.1 2>/dev/null");
    call_system("iptables -t mangle -D OUTPUT -p tcp --dport 80 -j MARK --set-mark 1 2>/dev/null");

    */
    call_system("ip rule del ipproto udp table 1 2/dev/null");
    call_system("ip route del table 1 default via 10.0.0.1 2>/dev/null");
    call_system("ip rule del fwmark 1 table 1 2>/dev/null");
    call_system("ip rule del ipproto udp table 1 2>/dev/null");
    call_system("ip route flush table 1");
    call_system("ip route flush cache");
}
