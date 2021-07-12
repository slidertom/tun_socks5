#pragma once

#include <cstddef>

class Connection
{
public:
    Connection() { }
    Connection(const Connection &x) = delete;
    Connection(Connection &&x) = delete;
    virtual ~Connection() { }

public:
    virtual void HandleEvent() = 0;
    virtual bool SendPacket(const std::byte *buffer, size_t size) { return false; }

protected:
    std::byte m_buffer[65535];
};
