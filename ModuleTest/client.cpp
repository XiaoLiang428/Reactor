#include "Socket.hpp"
#include <cstring>
#include <iostream>
#include <unistd.h>
int main() {
    std::cout << "Client started" << std::endl;
    Socket client_socket;
    client_socket.CreateClient(8888, "127.0.0.1");
    for (int i = 0; i < 5; i++) {
        const char *msg = "Hello from client";
        client_socket.Send((void *)msg, strlen(msg));
        char buffer[1024];
        ssize_t n = client_socket.Recv(buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            std::cout << "Received from server: " << buffer << std::endl;
        }
        sleep(1);
    }
    sleep(20);
    return 0;
}