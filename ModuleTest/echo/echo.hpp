#include "../server.hpp"
class EchoServer {
    using PTRConnection = std::shared_ptr<Connection>;

private:
    TcpServer _server;

private:
    void MessageCallback(const PTRConnection &conn, Buffer *buffer) {
        size_t len = buffer->ReadAbleSize();
        std::string req(buffer->ReadPosition(), len);
        buffer->MoveReadOffset(len);
        std::string body = "OK";
        std::string resp = "HTTP/1.0 200 OK\r\nContent-Length: " + std::to_string(body.size())
                           + "\r\nConnection: close\r\n\r\n" + body;
        conn->Send(resp.c_str(), resp.size());
        conn->ShutDown();  // 主动关闭让 WebBench 立即统计成功
    }
    void ConnectionCallback(const PTRConnection &conn) {
        LOG_INFO("Connection %lu established", conn->GetConnId());
    }
    void CloseCallback(const PTRConnection &conn) { LOG_INFO("Connection %lu destroyed", conn->GetConnId()); }

public:
    EchoServer(uint16_t port)
            : _server(port) {
        _server.SetConnectionCallback(
            std::bind(&EchoServer::ConnectionCallback, this, std::placeholders::_1));
        _server.SetMessageCallback(
            std::bind(&EchoServer::MessageCallback, this, std::placeholders::_1, std::placeholders::_2));
        _server.SetCloseCallback(std::bind(&EchoServer::CloseCallback, this, std::placeholders::_1));
        _server.SetThreadCount(5);
    }
    void Start() { _server.Start(); }
};