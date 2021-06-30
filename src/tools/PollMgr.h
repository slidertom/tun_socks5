#pragma once

#include "unordered_map"

class Connection;

// https://www.ulduzsoft.com/2014/01/select-poll-epoll-practical-difference-for-system-architects/
class PollMgr final
{
public:
    PollMgr();
    ~PollMgr();

// Operations
public:
    bool Add(int fd, Connection *pConn) noexcept;
    void Delete(int fd) noexcept;
    void Wait() const noexcept;

// Attributes
private:
    int m_fdPoll;
    std::unordered_map<int, Connection *> m_conns; // just manage by our self

private:
    PollMgr(PollMgr &&x) = delete;
    PollMgr(const PollMgr &x) = delete;
    PollMgr &operator=(PollMgr &&x) = delete;
    PollMgr &operator=(const PollMgr &x) = delete;
};
