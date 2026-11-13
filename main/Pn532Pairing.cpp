#include "Pn532Reader.hpp"
#include "esp_timer.h"
#include <algorithm>
#include <mutex>
#include <string>

namespace {
std::mutex pairingMutex;
std::string pendingUri;

bool exchange(pn532::Transport& bus, const std::vector<uint8_t>& command,
              std::vector<uint8_t>& response, uint32_t timeout) {
    using pn532::Status;
    const uint8_t length = command.size() + 1;
    std::vector<uint8_t> frame{0, 0, 255, length, uint8_t(-length), 0xd4};
    uint8_t sum = 0xd4;
    for (auto value : command) {
        frame.push_back(value);
        sum += value;
    }
    frame.push_back(uint8_t(-sum));
    frame.push_back(0);
    auto txn = bus.begin();
    std::array<uint8_t, 6> header{};
    if (!txn || txn.write(frame) != Status::SUCCESS || txn.waitForAck() != Status::SUCCESS ||
        txn.waitForResponse(timeout) != Status::SUCCESS || txn.read(header) != Status::SUCCESS ||
        header[0] || header[1] || header[2] != 255 || header[3] < 2 ||
        uint8_t(header[3] + header[4]) != 0 || header[5] != 0xd5) return false;
    response.resize(header[3] + 1);
    if (txn.read(response) != Status::SUCCESS || response.front() != command.front() + 1 ||
        response.back() != 0) return false;
    sum = 0xd5;
    for (auto value : response) sum += value;
    response.resize(response.size() - 2);
    return sum == 0;
}
}

bool Pn532Reader::requestPairing(std::string uri) {
    std::lock_guard guard(pairingMutex);
    if (!pendingUri.empty()) return false;
    pendingUri = std::move(uri);
    return true;
}

void Pn532Reader::servePairing() {
    std::string uri;
    {
        std::lock_guard guard(pairingMutex);
        uri.swap(pendingUri);
    }
    if (uri.empty()) return;
    std::vector<uint8_t> ndef{0, uint8_t(uri.size() + 5), 0xd1, 1,
                              uint8_t(uri.size() + 1), 'U', 0};
    ndef.insert(ndef.end(), uri.begin(), uri.end());
    const std::vector<uint8_t> cc{0,15,0x20,0,59,0,52,4,6,0xe1,4,0,64,0,255};
    const std::vector<uint8_t> aid{0xd2,0x76,0,0,0x85,1,1};
    std::vector<uint8_t> start(38, 0);
    start[0]=0x8c; start[1]=5; start[2]=4; start[4]=0x12;
    start[5]=0x34; start[6]=0x56; start[7]=0x20;
    std::vector<uint8_t> data;
    const auto deadline = esp_timer_get_time() + 30'000'000;
    (void)m_frontend->RFConfiguration(0x01, {0});
    while (esp_timer_get_time() < deadline) {
        if (!exchange(*m_transport, start, data, 1500)) {
            m_transport->abort();
            continue;
        }
        const std::vector<uint8_t>* file = nullptr;
        bool selected = false;
        while (esp_timer_get_time() < deadline &&
               exchange(*m_transport, {0x86}, data, 1200) && data.size() >= 6 && data[1] == 0) {
            const auto* apdu = data.data() + 2;
            const auto size = data.size() - 2;
            std::vector<uint8_t> reply{0x8e};
            uint16_t status = 0x6a82;
            if (size >= 5 && apdu[0] == 0) {
                if (apdu[1] == 0xa4 && apdu[2] == 4 && apdu[4] == aid.size() &&
                    size >= 5 + aid.size() && std::equal(aid.begin(), aid.end(), apdu + 5)) {
                    selected = true;
                    file = nullptr;
                    status = 0x9000;
                } else if (selected && apdu[1] == 0xa4 && apdu[2] == 0 &&
                           apdu[4] == 2 && size >= 7 && apdu[5] == 0xe1) {
                    file = apdu[6] == 3 ? &cc : apdu[6] == 4 ? &ndef : nullptr;
                    if (file) status = 0x9000;
                } else if (file && apdu[1] == 0xb0) {
                    const size_t offset = (size_t(apdu[2]) << 8) | apdu[3];
                    const size_t count = apdu[4];
                    if (offset <= file->size() && count <= file->size() - offset) {
                        reply.insert(reply.end(), file->begin() + offset, file->begin() + offset + count);
                        status = 0x9000;
                    } else status = 0x6b00;
                }
            }
            reply.push_back(status >> 8);
            reply.push_back(status & 255);
            if (!exchange(*m_transport, reply, data, 1000)) break;
        }
        m_transport->abort();
    }
    if (!init()) stop();
}
