#include "Tun.h"

#include <cstdio>
#include <stdlib.h>

#include "../lib/tuntap.h"

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

	int mtu = tuntap_get_mtu(m_pDevice);
	mtu -= 20;
	tuntap_set_mtu(m_pDevice, mtu);

	if (::tuntap_up(m_pDevice) == -1) {
		return -3;
	}

	if (::tuntap_set_ip(m_pDevice, sIP, 24) == -1) {
		return -4;
	}

	::tuntap_set_nonblocking(m_pDevice, 1);

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
