#pragma once

#include <vector>
#include <stdint.h>

/* UI */

class cursor {
public:
    size_t pos = 0;
    std::vector<std::uint8_t> data = {};

    size_t len() {
        return data.size();
    }

    size_t remaining() {
        return len() - pos;
    }

    void reset(const std::vector<std::uint8_t>& new_data)
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

    const uint8_t* ptr()
    {
        return ((uint8_t*)data.data()) + pos;
    }
};