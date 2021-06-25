#pragma once

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
    static void SetUpIpv4();

    static void CleanUp();
    static void Start(const char *sProxyIP);
};
