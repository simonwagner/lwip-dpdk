#pragma once

#include <string>

/* UI */

class cursor {
public:
    size_t pos = 0;
    std::string data = "";

    size_t len() {
        return data.size();
    }

    size_t remaining() {
        return len() - pos;
    }

    void reset(const std::string& new_data)
    {
        data = new_data;
        pos = 0;
    }

    bool empty()
    {
        return pos == len();
    }

    void consume(size_t n)
    {
        pos += n;
    }

    const char* ptr()
    {
        return data.c_str() + pos;
    }
};