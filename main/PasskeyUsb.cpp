#include "PasskeyUsb.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tusb.h"

namespace {
constexpr uint8_t hidReportDescriptor[] = {
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x95, 0x40, 0x91, 0x02, 0xC0
};

constexpr uint16_t configLength = TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN;
constexpr uint8_t configDescriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, configLength, 0, 100),
    TUD_HID_INOUT_DESCRIPTOR(0, 0, HID_ITF_PROTOCOL_NONE,
                             sizeof(hidReportDescriptor), 0x01, 0x81, 64, 5)
};

QueueHandle_t receivedReports = nullptr;
}

extern "C" const uint8_t* tud_hid_descriptor_report_cb(uint8_t) {
    return hidReportDescriptor;
}

extern "C" uint16_t tud_hid_get_report_cb(uint8_t, uint8_t, hid_report_type_t,
                                           uint8_t*, uint16_t) {
    return 0;
}

extern "C" void tud_hid_set_report_cb(uint8_t instance, uint8_t reportId,
                                      hid_report_type_t type, const uint8_t* data,
                                      uint16_t length) {
    if (instance == 0 && reportId == 0 &&
        (type == HID_REPORT_TYPE_INVALID || type == HID_REPORT_TYPE_OUTPUT) &&
        length == PasskeyUsb::Report{}.size() && receivedReports) {
        xQueueSend(receivedReports, data, 0);
    }
}

bool PasskeyUsb::begin() {
    if (receivedReports) {
        return true;
    }
    receivedReports = xQueueCreate(16, sizeof(Report));
    if (!receivedReports) {
        return false;
    }

    tinyusb_config_t config = TINYUSB_DEFAULT_CONFIG();
    config.descriptor.full_speed_config = configDescriptor;
    if (tinyusb_driver_install(&config) != ESP_OK) {
        vQueueDelete(receivedReports);
        receivedReports = nullptr;
        return false;
    }
    return true;
}

bool PasskeyUsb::receive(Report& report) {
    return receivedReports && xQueueReceive(receivedReports, report.data(), 0) == pdTRUE;
}

bool PasskeyUsb::send(const Report& report) {
    return tud_hid_ready() && tud_hid_report(0, report.data(), report.size());
}
