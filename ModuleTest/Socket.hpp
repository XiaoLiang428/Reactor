#pragma once
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctime>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "log_config.hpp"
class Socket {
private:
    int _socketfd;

public:
    Socket() : _socketfd(-1) {}
    Socket(int fd) : _socketfd(fd) {}
    ~Socket() { Close(); }
    // 创建socket
    bool Create()
    {
        _socketfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(_socketfd < 0)
        {
            LOG_ERROR("SOCKET CREATE ERROR");
            return false;
        }
        return true;
    }
    // 绑定ip和端口
    bool Bind(const std::string &ip, uint16_t port)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
        if(bind(_socketfd,(struct sockaddr*)&addr,sizeof(addr)) < 0)
        {
            LOG_ERROR("SOCKET BIND ERROR");
            return false;
        }
        return true;
    }
    // 设置为监听模式
    bool Listen(int backlog = DefaultBackLog)
    {
        int ret = listen(_socketfd, backlog);
        if (ret < 0)
        {
            LOG_ERROR("SOCKET LISTEN ERROR");
            return false;
        }
        return true;
    }
    //建立连接
    bool Connect(const std::string &ip, uint16_t port)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
        int ret = connect(_socketfd,(struct sockaddr*)&addr,sizeof(addr));
        if(ret < 0)
        {
            LOG_ERROR("SOCKET CONNECT ERROR");
            return false;
        }
        return true;
    }
    // 获取新连接并返回新的连接描述符
    int Accept()
    {
        //不关心客户端的ip和端口信息
        int newfd = accept(_socketfd, nullptr, nullptr);
        if (newfd < 0)
        {
            LOG_ERROR("SOCKET ACCEPT ERROR");
            return -1;
        }
        return newfd;
    }
    ssize_t Recv(void *buffer, size_t len, int flag = 0)
    {
        ssize_t ret = recv(_socketfd, buffer, len, flag);
        if (ret <= 0) // 出错或者对端关闭连接
        {
            if(ret == EAGAIN || ret == EWOULDBLOCK)
            {
                LOG_DEBUG("SOCKET RECV ERROR AGAIN");
            }
            else
            {
                LOG_ERROR("SOCKET RECV ERROR");
            }
            return -1;
        }
        return ret;
    }
    ssize_t NonBlockRecv(void *buffer, size_t len)
    {
        return Recv(buffer, len, MSG_DONTWAIT);
    }
    ssize_t Send(void *buffer, size_t len, int flag = 0)
    {
        ssize_t ret = send(_socketfd, buffer, len, flag);
        if (ret <= 0) // 出错或者对端关闭连接
        {
            if(ret == EAGAIN || ret == EWOULDBLOCK)
            {
                LOG_DEBUG("SOCKET SEND ERROR AGAIN");
            }
            else
            {
                LOG_ERROR("SOCKET SEND ERROR");
            }
        }
        return ret;
    }
    ssize_t NonBlockSend(void *buffer, size_t len)
    {
        return Send(buffer, len, MSG_DONTWAIT);
    }
    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0" ,bool flag = 0)
    {
        //1.创建socket
        if(Create() == false) return false;

        // 2.绑定ip和端口
        if(Bind(ip,port) == false) return false;
        // 3.设置为监听模式
        if(Listen() == false) return false;
        //设置套接字为非阻塞
        //if(flag) 
        SetNonBlock();
        //复用地址
        ReuseAddress();
        return true;
    }
    bool CreateClient(uint16_t port, const std::string &ip)
    {
        //1.创建socket
        if(Create() == false) return false;
        //无需手动绑定ip和端口号，系统自动分配从而防止端口号冲突
        //2.连接服务器
        if(Connect(ip,port) == false) return false;
        return true;
    }
    bool Close()
    {
        if(_socketfd != -1)
        {
            close(_socketfd);
            _socketfd = -1;
        }
        return true;
    }
    void ReuseAddress()
    {
        int opt = 1;
        setsockopt(_socketfd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt));
        opt = 1;
        setsockopt(_socketfd, SOL_SOCKET, SO_REUSEPORT, (void*)&opt, sizeof(opt));
    }
    void SetNonBlock()
    {
        int flags = fcntl(_socketfd, F_GETFL, 0);
        fcntl(_socketfd, F_SETFL, flags | O_NONBLOCK);
    }
    int Fd() { return _socketfd; }
};