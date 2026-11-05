#pragma once

#include <cstdio>

#define IDS_LOG(tag, format, ...) \
    do { \
        char log_buffer[512]; \
        std::snprintf(log_buffer, sizeof(log_buffer), "[" tag "] " format, ##__VA_ARGS__); \
        std::printf("%s\n", log_buffer); \
    } while (false)

#define LOG_INFO(category, format, ...) IDS_LOG(category, format, ##__VA_ARGS__)
#define LOG_WARN(category, format, ...) IDS_LOG("WARN " category, format, ##__VA_ARGS__)
#define LOG_ERROR(category, format, ...) IDS_LOG("ERROR " category, format, ##__VA_ARGS__)
