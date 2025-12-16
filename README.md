该项目实现了一个基于 主从 Reactor (Master-Slave Reactor) 模式的多线程网络服务器框架。

核心功能总结如下：

事件驱动的非阻塞 I/O：
使用 EventLoop 作为事件循环的核心，底层通过 epoll 封装（在 Poller 类中）来监听文件描述符上的 I/O 事件（读、写、连接、关闭等）。
Channel 类负责封装文件描述符及其关心的事件和回调函数，是 Reactor 模式中事件分发的基本单元。

主从 Reactor 多线程模型：
主 Reactor (Master)：在 main 函数中创建的 TcpServer 内部包含一个 _base_loop，它只负责运行 Acceptor 来监听和接受新的客户端连接。
从 Reactors (Slaves)：通过 SetThreadCount(2) 创建了一个包含 2 个工作线程的 LoopThreadPool。每个工作线程都运行一个独立的 EventLoop。
当主 Reactor 接受一个新连接后，它会通过轮询（Round-Robin）策略将这个新连接的 Connection 对象分发给一个从 Reactor（工作线程）来处理，从而实现负载均衡。

连接管理与封装：
Connection 类封装了与客户端连接相关的所有信息和操作，包括套接字、输入/输出缓冲区 (Buffer)、以及对应的 Channel。
TcpServer 内部使用一个 std::unordered_map (_conns) 来管理所有活跃的连接，通过 shared_ptr 进行生命周期管理。

应用层逻辑解耦：
框架通过设置回调函数（SetConnectionCallback, SetMessageCallback, SetCloseCallback）的方式，将网络层的事件处理与上层的业务逻辑（如 OnMessage 中的回显逻辑）分离开。
当前 main 函数中的示例实现了一个简单的 Echo 服务器：当收到客户端消息时，会将其原样返回，并在前面加上 "Server receive your message: "。

闲置连接自动释放：
通过 SetInactiveReleaseTime(10) 和内部的 TimeWheel（时间轮）机制，服务器可以检测并自动断开超过 10 秒没有活动的闲置连接，防止资源泄露。

简而言之，这是一个具备高性能、高并发潜力的 C++ 网络库，它封装了底层的 epoll 和线程管理，为上层应用（如当前的 Echo 服务或之前的 HTTP 服务）提供了一套简洁、事件驱动的编程接口。
