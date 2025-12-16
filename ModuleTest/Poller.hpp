#pragma once
#include "log_config.hpp"
#include <cerrno>
#include <cstdlib>
#include <sys/epoll.h>
#include <unordered_map>
#include "Channel.hpp"
#include <unistd.h>
#include <vector>
#include <cassert>
#include <cstring>
#define MAXEVENTS 1024
class Channel;
class Poller
{
    private:
        int _epfd;
        struct epoll_event _events[MAXEVENTS];
        std::unordered_map<int,Channel*> _channels;
    private:
        void Update(Channel* channel,int op)
        {
            struct epoll_event ev;
            ev.data.fd = channel->Fd();
            ev.events = channel->Events();
            if(epoll_ctl(_epfd,op,channel->Fd(),&ev) < 0)
            {
                LOG_ERROR("EPOLL CTL ERROR");
            }
        }
        bool CheckChannel(Channel* channel)
        {
            int fd = channel->Fd();
            auto it = _channels.find(fd);
            if(it == _channels.end())
            {
                return false;
            }
            return true;
        }
    public:
        Poller() 
        {
            _epfd = epoll_create(MAXEVENTS);
            if(_epfd < 0)
            {
                LOG_ERROR("EPOLL CREATE ERROR");
            }
        }
        ~Poller() 
        {
            close(_epfd);
        }
        void UpdateEvent(Channel* channel)
        {
            if(CheckChannel(channel) == false)
            {
                //新增channel
                Update(channel,EPOLL_CTL_ADD);
                _channels[channel->Fd()] = channel;
            }
            else
            {
                //修改channel
                Update(channel,EPOLL_CTL_MOD);
            }
        }
        void RemoveEvent(Channel* channel)
        {
            if(CheckChannel(channel) == false)
            {
                return;
            }
            Update(channel,EPOLL_CTL_DEL);
            _channels.erase(channel->Fd());
        }
        void Poll(std::vector<Channel*> *actvie)
        {
            int nfds = epoll_wait(_epfd,_events,MAXEVENTS,-1);
            if(nfds < 0)
            {
                if(errno == EINTR)
                {
                    return;
                }
                LOG_ERROR("EPOLL WAIT ERROR,%s\n",strerror(errno));
                abort();
            }
            for(int i = 0; i < nfds; ++i)
            {
                int fd = _events[i].data.fd;
                auto it = _channels.find(fd);
                assert(it != _channels.end());
                Channel* channel = it->second;
                channel->SetREvents(_events[i].events);
                actvie->push_back(channel);
            }
        }
};