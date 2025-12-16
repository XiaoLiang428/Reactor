#pragma once
#include "../server.hpp"
#include <fstream>
#include <regex>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

class Util {
public:
    static int HexToI(int c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        } else if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        } else {
            return -1;
        }
    }
    // 字符串分割
    // 将str按照sep进行分割，结果存入out中，返回分割出的字符串个数
    static size_t SplitString(const std::string str, const std::string sep, std::vector<std::string> *out) {
        size_t offset = 0;
        while (offset < str.size()) {
            size_t pos = str.find(sep, offset);
            if (pos == std::string::npos) {
                // 说明找到了字符串的末尾
                out->push_back(str.substr(offset, str.size() - offset));
                return out->size();
            }
            if (pos != offset)  // 如果内容为空就不加入到结果中
                out->push_back(str.substr(offset, pos - offset));
            offset = pos + sep.size();  // 移动偏移量
        }
        return out->size();
    }
    // 读取文件内容 将文件的内容放入一个Buffer对象中
    static bool ReadFile(const std::string &filename, std::string *buf) {
        std::ifstream ifs(filename, std::ios::binary);
        if (!ifs.is_open()) {
            LOG_INFO("ReadFile %s failed", filename.c_str());
            return false;
        }
        // 获取文件的大小然后一次性读取
        ifs.seekg(0, ifs.end);            // 将读写位置跳转到文件末尾
        size_t file_size = ifs.tellg();   // 获取当前位置与文件开头的偏移量即为文件大小
        ifs.seekg(0, ifs.beg);            // 将读写位置跳转到文件开头
        buf->resize(file_size);           // 预留空间
        ifs.read(&(*buf)[0], file_size);  // 读取文件内容
        if (ifs.good() == false) {
            LOG_INFO("ReadFile %s failed during read", filename.c_str());
            ifs.close();
            return false;
        }
        ifs.close();
        return true;
    }
    // 向文件中写入内容
    static bool WriteFile(const std::string &filename, const std::string &buf) {
        std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);  // 以二进制写入且清空原有内容
        if (ofs.is_open() == false) {
            LOG_INFO("WriteFile %s failed", filename.c_str());
            return false;
        }
        ofs.write(buf.data(), buf.size());
        if (ofs.good() == false) {
            LOG_INFO("WriteFile %s failed during write", filename.c_str());
            ofs.close();
            return false;
        }
        ofs.close();
        return true;
    }
    // Url编码
    // RFC3986文档 绝对不编码字符 数字 大小写字母 - _ . ~
    // W3C标准规定 空格需要转化为+
    // RFC2396文档规定Url保留字符需要转化为%HH格式
    static std::string UrlEncode(const std::string &url, bool convert_sep_to_plus) {
        std::string result;
        for (auto &c : url) {
            if (c == '-' || c == '_' || c == '.' || c == '~'
                || isalnum(c))  // isalnum可以判断字符是否为数字或字母
            {
                // 不编码字符
                result += c;
                continue;
            } else if (c == ' ' && convert_sep_to_plus) {
                // 空格转化为+
                result += '+';
            } else {
                // 其他字符转化为%HH格式
                char buf[4] = {0};
                snprintf(buf, 4, "%%%02X", c);
                result += buf;
            }
        }
        return result;
    }
    // Url解码
    static std::string UrlDecode(const std::string &url, bool convert_plus_to_space) {
        std::string result;
        for (int i = 0; i < url.size(); i++) {
            if (url[i] == '%' && i + 2 < url.size()) {
                int high = HexToI(url[i + 1]);
                int low = HexToI(url[i + 2]);
                if (high != -1 && low != -1) {
                    char decoded_char = (high << 4) | low;
                    result += decoded_char;
                    i += 2;  // 跳过已经处理的两个字符
                }
            } else if (url[i] == '+' && convert_plus_to_space == true) {
                // + 转化为空格
                result += ' ';
            } else {
                result += url[i];
            }
        }
        return result;
    }
    // 获取文件状态
    static std::string StatusDesc(int code) {
        std::unordered_map<int, std::string> status_map = {
            {100, "Continue"},
            {101, "Switching Protocols"},
            {200, "OK"},
            {201, "Created"},
            {202, "Accepted"},
            {203, "Non-Authoritative Information"},
            {204, "No Content"},
            {205, "Reset Content"},
            {206, "Partial Content"},
            {300, "Multiple Choices"},
            {301, "Moved Permanently"},
            {302, "Found"},
            {303, "See Other"},
            {304, "Not Modified"},
            {305, "Use Proxy"},
            {307, "Temporary Redirect"},
            {400, "Bad Request"},
            {401, "Unauthorized"},
            {402, "Payment Required"},
            {403, "Forbidden"},
            {404, "Not Found"},
            {405, "Method Not Allowed"},
            {406, "Not Acceptable"},
            {407, "Proxy Authentication Required"},
            {408, "Request Time-out"},
            {409, "Conflict"},
            {410, "Gone"},
            {411, "Length Required"},
            {412, "Precondition Failed"},
            {413, "Request Entity Too Large"},
            {414, "Request-URI Too Large"},
            {415, "Unsupported Media Type"},
            {416, "Requested range not satisfiable"},
            {417, "Expectation Failed"},
            {500, "Internal Server Error"},
            {501, "Not Implemented"},
            {502, "Bad Gateway"},
            {503, "Service Unavailable"},
            {504, "Gateway Time-out"},
            {505, "HTTP Version not supported"}};
        auto it = status_map.find(code);
        if (it == status_map.end()) {
            return "Unknown Status";
        }
        return it->second;
    }
    // 获取文件Mime
    static std::string ExternMime(const std::string &filename) {
        size_t pos = filename.find_last_of('.');
        if (pos == std::string::npos)
            return "application/octet-stream";  // 默认二进制流
        std::string ext = filename.substr(pos + 1);
        static std::unordered_map<std::string, std::string> mime_map = {
            // 文本与文档类型
            {"txt", "text/plain"},
            {"html", "text/html"},
            {"htm", "text/html"},
            {"css", "text/css"},
            {"csv", "text/csv"},
            {"xml", "text/xml"},

            // 图像类型
            {"jpg", "image/jpeg"},
            {"jpeg", "image/jpeg"},
            {"png", "image/png"},
            {"gif", "image/gif"},
            {"bmp", "image/bmp"},
            {"webp", "image/webp"},
            {"svg", "image/svg+xml"},
            {"ico", "image/x-icon"},

            // 应用程序与二进制文件
            {"pdf", "application/pdf"},
            {"json", "application/json"},
            {"zip", "application/zip"},
            {"rar", "application/vnd.rar"},
            {"7z", "application/x-7z-compressed"},
            {"tar", "application/x-tar"},
            {"gz", "application/gzip"},
            {"exe", "application/x-msdownload"},
            {"doc", "application/msword"},
            {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            {"xls", "application/vnd.ms-excel"},
            {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
            {"ppt", "application/vnd.ms-powerpoint"},
            {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
            {"odt", "application/vnd.oasis.opendocument.text"},

            // 音频与视频类型
            {"mp3", "audio/mpeg"},
            {"wav", "audio/wav"},
            {"ogg", "audio/ogg"},
            {"aac", "audio/aac"},
            {"mp4", "video/mp4"},
            {"avi", "video/x-msvideo"},
            {"mpeg", "video/mpeg"},
            {"mpg", "video/mpeg"},
            {"webm", "video/webm"},
            {"ogv", "video/ogg"},

            // 字体类型
            {"ttf", "font/ttf"},
            {"otf", "font/otf"},
            {"woff", "font/woff"},
            {"woff2", "font/woff2"},

            // JavaScript
            {"js", "application/javascript"},
            {"mjs", "application/javascript"}  // 可以根据需要添加更多的扩展名和对应的MIME类型
        };
        auto it = mime_map.find(ext);
        if (it == mime_map.end())
            return "application/octet-stream";  // 默认二进制流
        return it->second;
    }
    // 判断该文件是否是目录
    static bool IsDir(const std::string &filename) {
        struct stat path_stat;
        if (stat(filename.c_str(), &path_stat) != 0) {
            return false;  // 无法获取文件状态，可能文件不存在
        }
        return S_ISDIR(path_stat.st_mode);
    }
    // 判断该文件是否是普通文件
    static bool IsRegular(const std::string &filename) {
        struct stat path_stat;
        if (stat(filename.c_str(), &path_stat) != 0) {
            return false;  // 无法获取文件状态，可能文件不存在
        }
        return S_ISREG(path_stat.st_mode);
    }
    // 判断文件路径是否有效
    // 用户只能在相对于某个根目录的范围内访问文件，防止目录遍历攻击
    static bool ValidPath(const std::string &path) {
        // 按照/来分割路径
        std::vector<std::string> subdirs;
        int ret = SplitString(path, "/", &subdirs);
        int level = 0;
        for (auto &dir : subdirs) {
            if (dir == "..") {
                level--;
                if (level < 0)
                    return false;  // 试图访问根目录之外
            } else if (dir == "." || dir.empty()) {
                // 当前目录或空字符串，忽略
                continue;
            } else
                level++;
        }
        return true;
    }
};

class HttpRequest {
public:
    std::string _method;
    std::string _url;
    std::string _version;
    std::string _body;
    std::smatch _matches;
    std::unordered_map<std::string, std::string> _headers;
    std::unordered_map<std::string, std::string> _params;

public:
    HttpRequest()
            : _version("HTTP/1.1") {}
    // 重置
    void Reset() {
        _method.clear();
        _url.clear();
        _version = "HTTP/1.1";
        _body.clear();
        std::smatch tmp;
        _matches.swap(tmp);
        _headers.clear();
        _params.clear();
    }
    // 插入头部字段
    void SetHeader(const std::string &key, const std::string &value) { _headers[key] = value; }
    // 检查头部字段
    bool HasHeader(const std::string &key) const {
        auto it = _headers.find(key);
        if (it == _headers.end())
            return false;
        return true;
    }
    // 获取头部字段的值
    std::string GetHeader(const std::string &key) const {
        auto it = _headers.find(key);
        if (it != _headers.end())
            return it->second;
        return "";
    }
    // 插入查询字符串
    void SetParam(const std::string &key, const std::string &value) { _params[key] = value; }
    // 检查查询字符串
    bool HasParam(const std::string &key) const {
        auto it = _params.find(key);
        if (it == _params.end())
            return false;
        return true;
    }
    // 获取查询字符串的值
    std::string GetParam(const std::string &key) const {
        auto it = _params.find(key);
        if (it != _params.end())
            return it->second;
        return "";
    }
    // 获取正文长度
    size_t ContentLength() const {
        if (HasHeader("Content-Length") == false) {
            return 0;
        }
        return std::stoul(GetHeader("Content-Length"));
    }
    // 判断是否是长连接
    bool Close() {
        if (HasHeader("Connection") && GetHeader("Connection") == "keep-alive")
            return false;  // 长连接
        return true;
    }
};

class HttpResponse {
public:
    int _status_code;           // 相应状态码
    bool _redirect_flag;        // 是否重定向
    std::string _redirect_url;  // 重定向地址
    std::string _body;          // 相应正文
    std::unordered_map<std::string, std::string> _headers;

public:
    HttpResponse()
            : _status_code(200)
            , _redirect_flag(false) {}
    HttpResponse(int code)
            : _status_code(code)
            , _redirect_flag(false) {}
    void ReSet() {
        _status_code = 200;
        _redirect_flag = false;
        _redirect_url.clear();
        _body.clear();
        _headers.clear();
    }
    void SetHeader(const std::string &key, const std::string &value) { _headers[key] = value; }
    bool HasHeader(const std::string &key) {
        auto it = _headers.find(key);
        if (it == _headers.end())
            return false;
        return true;
    }
    std::string GetHeader(const std::string &key) {
        auto it = _headers.find(key);
        if (it != _headers.end())
            return it->second;
        return "";
    }
    void SetContent(const std::string &body, const std::string &content_type) {
        _body = body;
        SetHeader("Content-Length", std::to_string(_body.size()));
        SetHeader("Content-Type", content_type);
    }
    void SetRedirect(const std::string &url, int status_code = 302) {
        _redirect_flag = true;
        _redirect_url = url;
        _status_code = status_code;
        SetHeader("Location", url);
    }
    bool Close() {
        if (HasHeader("Connection") && GetHeader("Connection") == "keep-alive")
            return false;  // 长连接
        return true;
    }
};

typedef enum {
    RECV_STATE_ERROR,
    RECV_STATE_LINE,
    RECV_STATE_HEAD,
    RECV_STATE_BODY,
    RECV_STATE_OVER
} HttpRecvState;
#define MAX_LINE 8192
class HttpContext {
private:
    int _resp_state;            // 响应状态码
    HttpRecvState _recv_state;  // 接收状态码
    HttpRequest _request;

private:
    bool RecvHttpLine(Buffer *buf)  // 从Buffer中读取数据
    {
        std::string line = buf->GetLine();
        if (line.size() == 0)  // 说明没有读取到数据
        {
            // 存在数据但是没有换行符
            if (buf->ReadAbleSize() > MAX_LINE) {
                // 请求行过于长，不符合要求
                _resp_state = 414;
                _recv_state = RECV_STATE_ERROR;
                return false;
            }
        }
        buf->MoveReadOffset(line.size());
        if (line.size() > MAX_LINE) {
            // 说明请求行过长
            _resp_state = 414;
            _recv_state = RECV_STATE_ERROR;
            return false;
        }
        return ParseHttpLine(line);
    }
    bool ParseHttpLine(std::string &line) {
        std::smatch matches;
        // std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1.\\.[01])(?:\n|\r\n)?");  //
        // 忽略大小写
        std::regex e(
            R"(^(GET|HEAD|POST|PUT|DELETE)\s+([^\s\?]+)(?:\?([^\s#]*))?\s+(HTTP/1\.[01])\r?\n?$)",
            std::regex::icase);
        bool ret = regex_match(line, matches, e);
        if (ret == false) {
            _resp_state = 400;
            _recv_state = RECV_STATE_ERROR;
            return false;
        }
        // 0 原url
        // 1 GET 方法
        // 2 url
        // 3 key=val&key=val……
        // 4 HTTP版本
        _request._method = matches[1];
        std::transform(_request._method.begin(), _request._method.end(), _request._method.begin(), ::toupper);
        _request._url = Util::UrlDecode(matches[2], false);
        _request._version = matches[4];
        std::vector<std::string> query_string_array;
        std::string query_string = matches[3];
        // 将键值对分组方便分离key val
        Util::SplitString(query_string, "&", &query_string_array);
        for (auto &str : query_string_array) {
            size_t pos = str.find("=");
            if (pos == std::string::npos) {
                _resp_state = 400;
                _recv_state = RECV_STATE_ERROR;
                return false;
            }
            std::string key = Util::UrlDecode(str.substr(0, pos), true);
            std::string val = Util::UrlDecode(str.substr(pos + 1), true);
            _request.SetParam(key, val);
        }
        _recv_state = RECV_STATE_HEAD;
        return true;
    }
    bool RecvHttpHead(Buffer *buf) {
        // 一行一行取出数据即可
        if (_recv_state != RECV_STATE_HEAD)
            return false;
        while (true) {
            std::string line = buf->GetLine();
            if (line.size() == 0)  // 说明没有读取到数据
            {
                // 存在数据但是没有换行符
                if (buf->ReadAbleSize() > MAX_LINE) {
                    // 请求行过于长，不符合要求
                    _resp_state = 414;
                    _recv_state = RECV_STATE_ERROR;
                    return false;
                }
            }
            buf->MoveReadOffset(line.size());
            if (line.size() > MAX_LINE) {
                // 说明请求行过长
                _resp_state = 414;
                _recv_state = RECV_STATE_ERROR;
                return false;
            }
            if (line == "\n" || line == "\r\n") {
                _recv_state = RECV_STATE_BODY;
                return true;  // 说明头部读取完毕
            }
            int ret = ParseHttpHead(line);
            if (ret == false)
                return false;
        }
        return true;
    }
    // 解析请求头
    bool ParseHttpHead(std::string &line) {
        if (line.back() == '\n')
            line.pop_back();
        if (line.back() == '\r')
            line.pop_back();
        size_t pos = line.find(": ");
        if (pos == std::string::npos) {
            _resp_state = 400;
            _recv_state = RECV_STATE_ERROR;
            return false;
        }
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 2);
        _request.SetHeader(key, val);
        //_recv_state = RECV_STATE_BODY;
        return true;
    }
    bool RecvHttpBody(Buffer *buf) {
        if (_recv_state != RECV_STATE_BODY)
            return false;
        // 1.判断该请求是否有正文
        if (_request.ContentLength() == 0) {
            _recv_state = RECV_STATE_OVER;
            return true;
        }
        // 2.存在正文 需要判断Buffer中是否存在足够的数据读取
        // 用ContentLength对应的长度减去目前正文就是还需要读取的正文长度
        size_t rest_len = _request.ContentLength() - _request._body.size();
        if (buf->ReadAbleSize() >= rest_len) {
            // Buffer中的数据大小大于需要读取的正文长度，说明可以读完
            _request._body.append(buf->ReadPosition(), rest_len);
            buf->MoveReadOffset(rest_len);
            _recv_state = RECV_STATE_OVER;
            return true;
        }
        // 说明正文还没有完整读取，需要等待下次数据到达，接收状态保持为RECV_STATE_BODY
        _request._body.append(buf->ReadPosition(), buf->ReadAbleSize());
        buf->MoveReadOffset(buf->ReadAbleSize());
        return true;
    }

public:
    HttpContext()
            : _resp_state(200)
            , _recv_state(RECV_STATE_LINE) {}
    void ReSet() {
        _resp_state = 200;
        _recv_state = RECV_STATE_LINE;
        _request.Reset();
    }
    int RespState() { return _resp_state; }            // 获取请求的响应状态码
    HttpRecvState RecvState() { return _recv_state; }  // 获取当前处理进度
    HttpRequest &Request() { return _request; }        // 获取http请求
    // 接收并解析http请求
    bool RecvHttpRequest(Buffer *buf) {
        // 无需使用break，因为需要顺序向下执行
        switch (_recv_state) {
        case RECV_STATE_LINE:
            RecvHttpLine(buf);
        case RECV_STATE_HEAD:
            RecvHttpHead(buf);
        case RECV_STATE_BODY:
            RecvHttpBody(buf);
        case RECV_STATE_OVER:
            break;
        case RECV_STATE_ERROR:
            return false;
        }
        return true;
    }
};

#define DEFAULT_TIMEOUT 10
class HttpServer {
    using PtrConnection = std::shared_ptr<Connection>;

private:
    TcpServer _server;
    using Handler = const std::function<void(const HttpRequest &, HttpResponse *)>;
    using Handlers = std::vector<std::pair<std::regex, Handler>>;
    Handlers _get_route;
    Handlers _post_route;
    Handlers _put_route;
    Handlers _delete_route;
    std::string _base_dir;

private:
    void ErrorHandler(const HttpRequest &req, HttpResponse *resp) {
        // 1.组织错误页面内容
        std::string body;
        body += "<html>";
        body += "<head>";
        body += "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />";
        body += "</head>";
        body += "<body>";
        body += "<h1>";
        body += std::to_string(resp->_status_code) + " " + Util::StatusDesc(resp->_status_code);
        body += "</h1>";
        body += "<hr/>";
        body += "</body>";
        body += "</html>";
        // 2.为响应对象填充内容
        resp->SetContent(body, "text/html");
    }
    // 对功能性事件进行派发
    void Dispatcher(HttpRequest &req, HttpResponse *resp, Handlers &handlers) {
        // 在对应的方法路由表中进行查找，如果存在匹配的路由则调用对应的处理函数，反之则返回404
        for (auto &handler : handlers) {
            const std::regex re = handler.first;
            const Handler &functor = handler.second;
            bool ret = std::regex_match(req._url, req._matches, re);  // 将匹配结果存入req._matches中
            if (ret == false)
                continue;
            return functor(req, resp);
        }
        resp->_status_code = 404;  // 未找到
        return;
    }
    // 路由
    void Route(HttpRequest &req, HttpResponse *resp) {
        // 1.对请求进行分辨，判断是静态资源请求还是功能性请求
        if (IsFileHandler(req) == true) {
            return FileHandler(req, resp);
        }
        if (req._method == "GET") {
            return Dispatcher(req, resp, _get_route);
        } else if (req._method == "POST") {
            return Dispatcher(req, resp, _post_route);
        } else if (req._method == "PUT") {
            return Dispatcher(req, resp, _put_route);
        } else if (req._method == "DELETE") {
            return Dispatcher(req, resp, _delete_route);
        }

        resp->_status_code = 405;  // 方法不被允许
        return;
    }
    bool IsFileHandler(const HttpRequest &req) {
        // 静态资源的路径必须已经设置
        if (_base_dir.empty() == true)
            return false;
        // 判断请求的方法
        if (req._method != "GET" && req._method != "HEAD")
            return false;
        // 判断请求的url是否合法
        if (Util::ValidPath(req._url) == false)
            return false;
        std::string real_path = _base_dir + req._url;
        if (!real_path.empty() && real_path.back() == '/')
            real_path += "index.html";
        // 判断该路径是否存在且是一个普通文件
        if (Util::IsRegular(real_path) == false)
            return false;

        return true;
    }
    // 对静态资源获取
    void FileHandler(HttpRequest &req, HttpResponse *resp) {
        std::string req_path = _base_dir + req._url;
        if (req._url.back() == '/')
            req_path += "index.html";
        req._url = req_path;
        bool ret = Util::ReadFile(req._url, &resp->_body);
        if (ret == false) {
            resp->_status_code = 404;  // 未找到
            return;
        }
        std::string mime = Util::ExternMime(req._url);
        resp->SetHeader("Content-Type", mime);
        return;
    }
    // 生成http Response格式的内容进行发送
    void WriteResponse(const PtrConnection &conn, HttpRequest &req, HttpResponse *resp) {
        // 1.完善头部字段
        if (req.Close() == true) {
            resp->SetHeader("Connection", "close");
        } else {
            resp->SetHeader("Connection", "keep-alive");
        }
        if (resp->HasHeader("Content-Length") == false) {
            resp->SetHeader("Content-Length", std::to_string(resp->_body.size()));
        }
        if (resp->_body.empty() == false && resp->HasHeader("Content-Type") == false) {
            resp->SetHeader("Content-Type", "application/octet-stream");
        }
        if (resp->_redirect_flag == true && resp->HasHeader("Location") == false) {
            resp->SetHeader("Location", resp->_redirect_url);
        }
        // 2.根据http协议的格式来组织内容
        std::stringstream resp_str;
        resp_str << "HTTP/1.1 " << resp->_status_code << " " << Util::StatusDesc(resp->_status_code)
                 << "\r\n";
        for (auto &header : resp->_headers) { resp_str << header.first << ": " << header.second << "\r\n"; }
        resp_str << "\r\n";  // 头部和正文之间需要有一个空行
        resp_str << resp->_body;
        LOG_INFO("Response:%s", resp_str.str().c_str());
        // 3.发送Response
        conn->Send(resp_str.str().c_str(), resp_str.str().size());
    }
    // 设置上下文
    void OnConnected(const PtrConnection &conn) {
        conn->SetContext(HttpContext());
        LOG_INFO("A new Connection:%p", conn.get());
    }
    // 对缓冲区数据进行分析和处理
    void OnMessage(const PtrConnection &conn, Buffer *buf) {
        // 1.获取上下文
        HttpContext *context = conn->GetContext()->get<HttpContext>();
        // 2.通过上下文对缓冲区的数据进行解析
        context->RecvHttpRequest(buf);

        HttpResponse resp(context->RespState());
        HttpRequest &req = context->Request();
        if (context->RespState() >= 400) {
            // 说明出错
            ErrorHandler(req, &resp);  // 为错误页面填充信息
            WriteResponse(conn, req, &resp);
            context->ReSet();//重置上下文，防止下次请求受到影响
            buf->MoveReadOffset(buf->ReadAbleSize()); // 清空缓冲区数据
            conn->ShutDown();
            return;
        }
        if (context->RecvState() != RECV_STATE_OVER) {
            // 说明数据还未接收完毕,还需要继续接收新数据
            return;
        }
        // 3.请求路由 + 业务分配
        Route(req, &resp);
        // 4.对HttpResponse进行发送
        WriteResponse(conn, req, &resp);
        // 5.重置上下文
        context->ReSet();
        // 6.判断长短连接
        if (resp.Close() == true)
            conn->ShutDown();
    }

public:
    HttpServer(uint16_t port, int timeout = DEFAULT_TIMEOUT)
            : _server(port) {
        _server.SetConnectionCallback(std::bind(&HttpServer::OnConnected, this, std::placeholders::_1));
        _server.SetMessageCallback(
            std::bind(&HttpServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
        _server.EnableInactiveRelease(timeout);
    }
    void Get(const std::string &pattern, Handler &Handler) {
        _get_route.push_back(make_pair(std::regex(pattern), Handler));
    }
    void Post(const std::string &pattern, Handler &Handler) {
        _post_route.push_back(make_pair(std::regex(pattern), Handler));
    }
    void Put(const std::string &pattern, Handler &Handler) {
        _put_route.push_back(make_pair(std::regex(pattern), Handler));
    }
    void Delete(const std::string &pattern, Handler &Handler) {
        _delete_route.push_back(make_pair(std::regex(pattern), Handler));
    }
    void SetBaseDir(const std::string &filepath) { _base_dir = filepath; }
    void SetThreadCount(int count) { _server.SetThreadCount(count); }
    void Listen() { _server.Start(); }
};