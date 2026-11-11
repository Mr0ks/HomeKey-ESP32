#pragma once

#include "PasskeyUsb.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

class Ctaphid {
public:
    using Report = PasskeyUsb::Report;
    using Send = bool (*)(const Report&);

    explicit Ctaphid(Send sendReport) : send(sendReport) {}

    // Returns a complete CBOR request. The caller owns the channel until finish().
    std::span<const uint8_t> receive(const Report& report, uint32_t nowMs);
    void tick(uint32_t nowMs);
    bool finish(std::span<const uint8_t> response);
    bool keepalive(uint8_t status);
    bool cancelled() const { return cancelRequested; }

private:
    bool reply(uint32_t channel, uint8_t command, std::span<const uint8_t> payload);
    void error(uint32_t channel, uint8_t status);
    std::span<const uint8_t> dispatch();

    static constexpr size_t maxPayload = 57 + 128 * 59;
    static constexpr uint32_t broadcast = 0xffffffff;
    static constexpr uint32_t frameTimeoutMs = 750;
    Send send;
    std::array<uint8_t, maxPayload> payload{};
    uint32_t lastAllocated = 0;
    uint32_t active = 0;
    uint32_t frameTime = 0;
    size_t length = 0;
    size_t received = 0;
    uint8_t command = 0;
    uint8_t sequence = 0;
    bool processing = false;
    bool cancelRequested = false;
};
