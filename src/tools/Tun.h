#pragma once

#include <sys/types.h>
#include <string>

struct device;

class Tun final
{
public:
    Tun() { }
    ~Tun() {
        Destroy();
    }

public:
    int Init(const char *sName, const char *sIP);
    void Destroy();

    int Read(char *buffer, size_t size);
    void Write(char *buffer, size_t size);

    int GetFd() const noexcept;
    const char *GetIP() const noexcept { return m_sIP.c_str(); }
    uint32_t GetIPAddr() const noexcept { return m_ip; }

private:
    struct device *m_pDevice {nullptr};
    std::string m_sIP;
    uint32_t m_ip {0};

private:
    Tun(const Tun &x) = delete;
    Tun(const Tun &&x) = delete;
    Tun &operator=(const Tun &x) = delete;
	Tun &operator=(Tun &&x) = delete;
};
