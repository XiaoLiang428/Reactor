#pragma once
#include <cstdio>
#include <ctime>
#include <pthread.h>
#define DefaultBackLog 1024
#define INFO 1
#define DEBUG 2
#define ERROR 3
#define LOG_LEVEL INFO
#define LOG(level, format, ...)                                                                \
    do {                                                                                       \
        if (level < LOG_LEVEL)                                                                 \
            break;                                                                             \
        time_t t = time(nullptr);                                                              \
        struct tm *lt = localtime(&t);                                                         \
        char timestr[32];                                                                      \
        strftime(timestr, sizeof(timestr) - 1, "%Y-%m-%d %H:%M:%S", lt);                       \
        fprintf(stdout, "[%lu %s %s:%d]" format "\n", (unsigned long)pthread_self(), timestr, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define LOG_INFO(format, ...) LOG(INFO, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) LOG(DEBUG, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LOG(ERROR, format, ##__VA_ARGS__)