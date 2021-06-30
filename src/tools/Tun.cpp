#include "Tun.h"

#include "../lib/tuntap.h"

#include <arpa/inet.h>

int Tun::Init(const char *sName, const char *sIP)
{
    if (m_pDevice) {
        ::tuntap_destroy(m_pDevice);
    }

    m_pDevice = ::tuntap_init();

	if (::tuntap_start(m_pDevice, TUNTAP_MODE_TUNNEL, TUNTAP_ID_ANY) == -1) {
		return -1;
	}

	if (::tuntap_set_ifname(m_pDevice, sName) == -1) {
        return -2;
	}

	if (::tuntap_up(m_pDevice) == -1) {
		return -3;
	}

	m_sIP = sIP;
	if (::tuntap_set_ip(m_pDevice, sIP, 31) == -1) {
		return -4;
	}

	::tuntap_set_nonblocking(m_pDevice, 1);

    ::inet_pton(AF_INET, sIP, &m_ip);

	return ::tuntap_get_fd(m_pDevice);
}

void Tun::Destroy()
{
    if (!m_pDevice) {
        return;
    }
    ::tuntap_destroy(m_pDevice);
    m_pDevice = nullptr;
}

int Tun::Read(char *buffer, size_t size)
{
    return ::tuntap_read(m_pDevice, (void *)buffer, size);
}

void Tun::Write(char *buffer, size_t size)
{
    const int nRet = ::tuntap_write(m_pDevice, (void *)buffer, size);
    if (nRet < 0) {
        std::perror("Tun::Write failed");
		exit(EXIT_FAILURE);
    }
}

int Tun::GetFd() const noexcept
{
    return ::tuntap_get_fd(m_pDevice);
}
