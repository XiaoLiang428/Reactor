#include "http.hpp"

#define DEFAULT_BASE_DIR "./wwwroot/"
std::string RequestStr(const HttpRequest& req)
{
    std::stringstream ss;
    ss << req._method << " " << req._url << " " << req._version << "\r\n";
    for(auto &it:req._params)
    {
        ss << it.first << ": " << it.second << "\r\n";
    }
    for(auto &it:req._headers)
    {
        ss << it.first << ": " << it.second << "\r\n";
    }
    ss << "\r\n";
    ss << req._body << "\r\n";
    return ss.str();
}
void Hello(const HttpRequest& req, HttpResponse* rsp)
{
    rsp->SetContent(RequestStr(req), "text/plain");
}
void Put(const HttpRequest& req, HttpResponse* rsp)
{
    rsp->SetContent(RequestStr(req), "text/plain");
}
void Delete(const HttpRequest& req, HttpResponse* rsp)
{
    rsp->SetContent(RequestStr(req), "text/plain");
}
void Post(const HttpRequest& req, HttpResponse* rsp)
{
    rsp->SetContent(RequestStr(req), "text/plain");
}
int main()
{
    LOG_DEBUG("thread_id = %ld", std::this_thread::get_id());
    HttpServer server(8400);
    server.SetThreadCount(5);
    server.SetBaseDir(DEFAULT_BASE_DIR);
    server.Get("/get", Hello);
    server.Post("/post", Post);
    server.Delete("/delete", Delete);
    server.Put("/put", Put);
    server.Post("/login",Hello);
    server.Listen();
    return 0;
}
