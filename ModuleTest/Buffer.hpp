#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

#define DefaultBufferSize 1024
class Buffer {
private:
    std::vector<char> _buffer;  // 使用vector来充当缓冲区
    size_t _reader_idx;         // 读下标
    size_t _writer_idx;         // 写下标
public:
    Buffer() {
        _buffer.resize(DefaultBufferSize);
        _reader_idx = 0;
        _writer_idx = 0;
    }
    char *Begin() { return &*_buffer.begin(); }
    // 获取当前读出起始地址
    char *ReadPosition() { return Begin() + _reader_idx; }
    // 获取当前写入起始地址
    char *WritePosition() { return Begin() + _writer_idx; }

    // 获取缓冲区前部空闲空间大小
    size_t HeadIdleSize() { return _reader_idx; }
    // 获取缓冲区后部空闲空间大小
    size_t TailIdleSize() { return _buffer.size() - _writer_idx; }

    // 获取可读数据大小
    size_t ReadAbleSize() { return _writer_idx - _reader_idx; }

    // 将读下标向后移动特定距离
    void MoveReadOffset(size_t len) {
        assert(len <= ReadAbleSize());  // 确保读取数据不越界
        _reader_idx += len;
    }
    // 将写下标向后移动特定距离
    void MoveWriteOffset(size_t len) {
        assert(len <= TailIdleSize());  // 确保能够放得下数据
        _writer_idx += len;
    }
    // 确保空间足够（如果空间足够就将数据前移，不够就直接扩容）
    void EnsureEnoughSpace(size_t len) {
        if (len <= TailIdleSize())  // 缓冲区后部的空闲空间足够
            return;
        if (len <= HeadIdleSize() + TailIdleSize())  // 缓冲区总体空闲空间足够
        {
            // 将数据拷贝到数组的起始位置
            std::copy(ReadPosition(), ReadPosition() + ReadAbleSize(), Begin());
            _writer_idx = ReadAbleSize();
            _reader_idx = 0;  // 注意_writer_idx与_reader_idx顺序！
            return;
        }
        // 说明数组中空闲区域的位置不足，此时直接扩容但不移动数据
        _buffer.resize(_buffer.size() + len);
        return;
    }
    // 写入数据
    void Write(const void *data, size_t len) {
        EnsureEnoughSpace(len);
        char *str = (char *)data;
        std::copy(str, str + len, WritePosition());
    }
    void WriteString(const std::string &str) { Write(&str[0], str.size()); }
    void WriteBuffer(Buffer &buffer) {
        Write(buffer.ReadPosition(), buffer.ReadAbleSize());  //?
    }
    void WriteAndPush(const void *data, size_t len) {
        Write(data, len);
        MoveWriteOffset(len);
    }
    void WriteStringAndPush(const std::string &str) {
        WriteString(str);
        MoveWriteOffset(str.size());
    }
    void WriteBufferAndPush(Buffer &buffer) {
        WriteBuffer(buffer);
        MoveWriteOffset(buffer.ReadAbleSize());
    }
    // 读取数据
    void Read(void *buffer, size_t len) {
        assert(len <= ReadAbleSize());
        std::copy(ReadPosition(), ReadPosition() + len, (char *)buffer);
    }
    void ReadAndPop(void *buf, size_t len) {
        Read(buf, len);
        MoveReadOffset(len);
    }
    std::string ReadAsString(size_t len) {
        assert(len <= ReadAbleSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);  //?
        return str;
    }
    std::string ReadAsStringAndPop(size_t len) {
        std::string str = ReadAsString(len);
        MoveReadOffset(len);
        return str;
    }

    char *GetCRLF() {
        char *res = (char *)memchr(ReadPosition(), '\n', ReadAbleSize());
        return res;
    }
    std::string GetLine() {
        char *crlf = GetCRLF();
        if (crlf) {
            size_t len = crlf - ReadPosition() + 1;  // 将\n也读出来
            return ReadAsStringAndPop(len);
        }
        return "";
    }
    std::string GetLineAndPop() {
        std::string line = GetLine();
        MoveReadOffset(line.size());
        return line;
    }
};