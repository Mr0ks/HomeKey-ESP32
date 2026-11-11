#pragma once

#include <cstdint>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

class PasskeyGate {
public:
    using Ticket = uint64_t;

    Ticket beginRequest() {
        portENTER_CRITICAL(&lock);
        expire();
        Ticket result = 0;
        if (pending == 0) {
            if (++generation == 0) {
                ++generation;
            }
            result = pending = generation;
            deadline = esp_timer_get_time() + timeoutUs;
        }
        portEXIT_CRITICAL(&lock);
        return result;
    }

    Ticket pendingRequest() {
        portENTER_CRITICAL(&lock);
        expire();
        const Ticket result = pending;
        portEXIT_CRITICAL(&lock);
        return result;
    }

    void approve(Ticket ticket) {
        portENTER_CRITICAL(&lock);
        expire();
        if (ticket != 0 && ticket == pending) {
            approved = true;
        }
        portEXIT_CRITICAL(&lock);
    }

    bool consumeApproval(Ticket ticket) {
        portENTER_CRITICAL(&lock);
        expire();
        const bool allowed = ticket != 0 && ticket == pending && approved;
        if (allowed) {
            clear();
        }
        portEXIT_CRITICAL(&lock);
        return allowed;
    }

    void cancel(Ticket ticket) {
        portENTER_CRITICAL(&lock);
        if (ticket != 0 && ticket == pending) {
            clear();
        }
        portEXIT_CRITICAL(&lock);
    }

private:
    void expire() {
        if (pending != 0 && esp_timer_get_time() >= deadline) {
            clear();
        }
    }

    void clear() {
        pending = 0;
        approved = false;
    }

    static constexpr int64_t timeoutUs = 15'000'000;
    portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
    Ticket generation = 0;
    Ticket pending = 0;
    int64_t deadline = 0;
    bool approved = false;
};

inline PasskeyGate passkeyGate;
