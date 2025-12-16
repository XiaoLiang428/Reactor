#include "server.hpp"


using PTRConnection = std::shared_ptr<Connection>;
int conn_id = 0;
std::unordered_map<uint64_t,PTRConnection> connections;
EventLoop base_loop; //主线程 只负责监听操作
LoopThreadPool* pool;
void OnMessage(const PTRConnection& conn,Buffer* buffer)
{
    size_t len = buffer->ReadAbleSize();
    std::string msg(buffer->ReadPosition(),len);
    LOG_INFO("RECEIVE MESSAGE FROM CONN[%lu]: %s",conn->GetConnId(),msg.c_str());
    buffer->MoveReadOffset(len);
    std::string response = "Server receive your message: " + msg;
    conn->Send(response.c_str(),response.size());
}
void DestroyConnection(const PTRConnection& conn)
{
    LOG_INFO("Connection %lu destroyed",conn->GetConnId());
}
void OnConnection(const PTRConnection& conn)
{  
    LOG_INFO("Connection %lu established",conn->GetConnId());
}
// void Acccepter(int fd)
// {
//     conn_id++;
//     EventLoop* loop = pool->GetNextLoop();
//     PTRConnection conn (new Connection(loop,conn_id,fd));
//     conn->SetConnectionCallback(std::bind(OnConnection, std::placeholders::_1));
//     conn->SetMessageCallback(std::bind(OnMessage, std::placeholders::_1, std::placeholders::_2));
//     conn->SetCloseCallback(std::bind(DestroyConnection, std::placeholders::_1));
//     conn->EnableInactiveRelease(10);
//     conn->Established();
//     connections.insert(make_pair(conn->GetConnId(),conn));
//     LOG_INFO("New connection %lu accepted",conn->GetConnId());
// }
int main() 
{
    TcpServer tsvr(8888);
    tsvr.SetThreadCount(2);
    tsvr.SetConnectionCallback(OnConnection);
    tsvr.SetMessageCallback(OnMessage);
    tsvr.SetCloseCallback(DestroyConnection);
    tsvr.SetInactiveReleaseTime(10);
    tsvr.Start();
    // pool = new LoopThreadPool(&base_loop);
    // pool->SetThreadCount(2);
    // pool->CreateDependedLoops();
    // Acceptor acceptor(&base_loop, 8888);
    // acceptor.SetAcceptCallback(std::bind(Acccepter, std::placeholders::_1));
    // acceptor.Listen();
    // base_loop.Start();
    return 0; 
}