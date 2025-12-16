#include "../server.hpp"
#include <sys/wait.h>
// int main() {
//     signal(SIGCHLD, SIG_IGN);  // 忽略管道信号
//     for (int i = 0; i < 10; i++) {
//         pid_t pid = fork();
//         if (pid == 0) {
//             Socket sock;
//             sock.CreateClient(8400, "127.0.0.1");
//             std::string req = "GET /get HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
//             while (true) {
//                 assert(sock.Send(req.c_str(), req.size()) > 0);
//                 char buffer[4096];
//                 memset(buffer, 0, sizeof(buffer));
//                 ssize_t ret = sock.Recv(buffer, sizeof(buffer) - 1);
//                 if (ret <= 0) {
//                     LOG_ERROR("RECV ERROR");
//                     continue;
//                 }
//                 printf("RECEIVE RESPONSE:\n%s\n", buffer);
//             }
//             sock.Close();
//             exit(0);
//         }
//     }
//     while(1) sleep(1);
//     return 0;
// }
// int main() {
//     Socket sock;
//     sock.CreateClient(8400, "127.0.0.1");
//     std::string req = "GET /get HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
//     while (true) {
//         assert(sock.Send(req.c_str(), req.size()) > 0);
//         char buffer[4096];
//         memset(buffer, 0, sizeof(buffer));
//         ssize_t ret = sock.Recv(buffer, sizeof(buffer) - 1);
//         if (ret <= 0) {
//             LOG_ERROR("RECV ERROR");
//             continue;
//         }
//         printf("RECEIVE RESPONSE:\n%s\n", buffer);
//         sleep(2);
//     }
//     sock.Close();
//     return 0;
// }
int main() {
    Socket sock;
    sock.CreateClient(8400, "127.0.0.1");
    //一次发送多条请求测试
    std::string req = "GET /get HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    req += "GET /get HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    req += "GET /get HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    while (true) {
        assert(sock.Send(req.c_str(), req.size()) > 0);
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        ssize_t ret = sock.Recv(buffer, sizeof(buffer) - 1);
        if (ret <= 0) {
            LOG_ERROR("RECV ERROR");
            continue;
        }
        printf("RECEIVE RESPONSE:\n%s\n", buffer);
        sleep(10);
    }
    sock.Close();
    return 0;
}