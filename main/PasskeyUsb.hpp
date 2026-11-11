#pragma once

#include <array>
#include <cstdint>

class PasskeyUsb {
public:
    using Report = std::array<uint8_t, 64>;

    static bool begin();
    static bool receive(Report& report);
    static bool send(const Report& report);
};
