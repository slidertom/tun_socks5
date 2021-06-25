#pragma once

class Connection
{
public:
    Connection() { }
    Connection(const Connection &x) = delete;
    Connection(Connection &&x) = delete;
    virtual ~Connection() { }

public:
    virtual void HandleEvent() = 0;

protected:
    char m_buffer[65535];
};
