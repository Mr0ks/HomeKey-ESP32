#include "Ctaphid.hpp"

#include <algorithm>

namespace {
constexpr uint8_t ping = 0x81;
constexpr uint8_t init = 0x86;
constexpr uint8_t cbor = 0x90;
constexpr uint8_t cancel = 0x91;
constexpr uint8_t keepaliveCommand = 0xbb;
constexpr uint8_t errorCommand = 0xbf;

uint32_t readChannel(const Ctaphid::Report& report) {
    return (uint32_t(report[0]) << 24) | (uint32_t(report[1]) << 16) |
           (uint32_t(report[2]) << 8) | report[3];
}

void writeChannel(uint8_t* destination, uint32_t channel) {
    destination[0] = channel >> 24;
    destination[1] = channel >> 16;
    destination[2] = channel >> 8;
    destination[3] = channel;
}
}

bool Ctaphid::reply(uint32_t channel, uint8_t opcode, std::span<const uint8_t> data) {
    if (data.size() > maxPayload) {
        return false;
    }

    Report report{};
    writeChannel(report.data(), channel);
    report[4] = opcode;
    report[5] = data.size() >> 8;
    report[6] = data.size();
    auto count = std::min(data.size(), report.size() - 7);
    std::copy_n(data.begin(), count, report.begin() + 7);
    if (!send(report)) {
        return false;
    }
    data = data.subspan(count);
    for (uint8_t index = 0; !data.empty(); ++index) {
        std::fill(report.begin() + 4, report.end(), 0);
        report[4] = index;
        count = std::min(data.size(), report.size() - 5);
        std::copy_n(data.begin(), count, report.begin() + 5);
        if (!send(report)) {
            return false;
        }
        data = data.subspan(count);
    }
    return true;
}

void Ctaphid::error(uint32_t channel, uint8_t status) {
    reply(channel, errorCommand, {&status, 1});
}

void Ctaphid::tick(uint32_t nowMs) {
    if (active && !processing && nowMs - frameTime >= frameTimeoutMs) {
        error(active, 0x05);
        active = 0;
    }
}

std::span<const uint8_t> Ctaphid::receive(const Report& report, uint32_t nowMs) {
    tick(nowMs);
    const uint32_t channel = readChannel(report);
    const uint8_t marker = report[4];
    if (channel == 0 || (channel == broadcast && marker != init) ||
        (channel != broadcast && channel > lastAllocated)) {
        error(channel, 0x0b);
        return {};
    }

    if (marker == init) {
        if (report[5] != 0 || report[6] != 8) {
            error(channel, 0x03);
            return {};
        }
        if (channel == active && processing) {
            cancelRequested = true;
        } else if (channel == active) {
            active = 0;
        }
        if (channel == broadcast && lastAllocated == broadcast - 1) {
            error(channel, 0x06);
            return {};
        }
        std::array<uint8_t, 17> response{};
        std::copy_n(report.begin() + 7, 8, response.begin());
        writeChannel(response.data() + 8, channel == broadcast ? ++lastAllocated : channel);
        response[12] = 2;    // CTAPHID protocol version
        response[16] = 0x0c; // CBOR and no legacy MSG support
        reply(channel, init, response);
        return {};
    }

    if (marker == cancel) {
        if (processing && channel == active && report[5] == 0 && report[6] == 0) {
            cancelRequested = true;
        }
        return {};
    }

    if (active && (active != channel || processing)) {
        if (marker & 0x80) {
            error(channel, 0x06);
        }
        return {};
    }

    size_t offset;
    if (marker & 0x80) {
        if (active) {
            error(channel, 0x04);
            active = 0;
            return {};
        }
        if (marker != ping && marker != cbor) {
            error(channel, 0x01);
            return {};
        }
        length = (size_t(report[5]) << 8) | report[6];
        if (length > payload.size() || (marker == cbor && length == 0)) {
            error(channel, 0x03);
            return {};
        }
        active = channel;
        command = marker;
        received = 0;
        sequence = 0;
        offset = 7;
    } else {
        if (!active) {
            return {};
        }
        if (marker != sequence++) {
            error(channel, 0x04);
            active = 0;
            return {};
        }
        offset = 5;
    }

    frameTime = nowMs;
    const auto count = std::min(length - received, report.size() - offset);
    std::copy_n(report.begin() + offset, count, payload.begin() + received);
    received += count;
    return received == length ? dispatch() : std::span<const uint8_t>{};
}

std::span<const uint8_t> Ctaphid::dispatch() {
    const std::span<const uint8_t> request{payload.data(), length};
    if (command == ping) {
        reply(active, ping, request);
        active = 0;
        return {};
    }
    processing = true;
    cancelRequested = false;
    return request;
}

bool Ctaphid::finish(std::span<const uint8_t> response) {
    if (!processing) {
        return false;
    }
    const uint8_t keepaliveCancel = 0x2d;
    const bool sent = reply(active, cbor, cancelRequested
        ? std::span<const uint8_t>{&keepaliveCancel, 1} : response);
    processing = false;
    active = 0;
    return sent;
}

bool Ctaphid::keepalive(uint8_t status) {
    return processing && reply(active, keepaliveCommand, {&status, 1});
}
