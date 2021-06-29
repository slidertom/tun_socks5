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

private:
    struct device *m_pDevice {nullptr};
    std::string m_sIP;

private:
    Tun(const Tun &x) = delete;
    Tun(const Tun &&x) = delete;
    Tun &operator=(const Tun &x) = delete;
	Tun &operator=(Tun &&x) = delete;
};
