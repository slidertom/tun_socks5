#include "PollMgr.h"

#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#include "Connection.h"

PollMgr::PollMgr()
{
    // Create the epoll descriptor. Only one is needed per app, and is used to monitor all sockets.
    // The function argument is ignored (it was not before, but now it is), so put your favorite number here
    m_fdPoll = epoll_create(0xCAFE);
}

PollMgr::~PollMgr()
{
    for (Connection *pConn : m_conns) {
        delete pConn;
    }


    if (m_fdPoll >= 0) {
        ::close(m_fdPoll);
    }
}

bool PollMgr::Add(int fd, Connection *pConn) noexcept
{
    // Initialize the epoll structure in case more members are added in future
    struct epoll_event ev {0};

    // https://man7.org/linux/man-pages/man2/epoll_ctl.2.html
    // EPOLLIN - read
    // EPOLLRDHUP  - Stream socket peer closed connection, or shut down writing
    // half of connection.  (This flag is especially useful for
    // writing simple code to detect peer shutdown when using
    // edge-triggered monitoring.)
    ev.events  = EPOLLIN|EPOLLRDHUP|EPOLLERR;
    ev.data.fd = fd;
    // Associate the connection class instance with the event. You can associate anything
    // you want, epoll does not use this information. We store a connection class pointer, pConnection1
    ev.data.ptr = pConn ? pConn : nullptr;

    const int res = epoll_ctl(m_fdPoll, EPOLL_CTL_ADD, fd, &ev);

    if (res == EEXIST) {
        return false; // please fix code logic
    }

    if (res < 0) {
        return false;
    }

    if (pConn) {
        m_conns.push_back(pConn);
    }

    return true;
}

void PollMgr::Wait() const noexcept
{
    constexpr int maxevents = 4;
    constexpr int timeout   = -1;
    struct epoll_event events[maxevents];
    const int ret = epoll_wait(m_fdPoll, events, maxevents, timeout);
    for (int i1 = 0; i1 < ret; ++i1) {
        if (events[i1].data.ptr) {
            Connection *pConn = (Connection *)events[i1].data.ptr;
            pConn->HandleEvent();
        }
    }
}
