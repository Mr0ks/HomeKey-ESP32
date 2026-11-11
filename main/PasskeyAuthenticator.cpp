#include "PasskeyAuthenticator.hpp"

#include "Ctaphid.hpp"
#include "PasskeyGate.h"
#include "cbor.h"
#include "esp_random.h"
#include "freertos/task.h"
#include "nvs.h"
#include "psa/crypto.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace {
using Bytes = std::span<const uint8_t>;
constexpr size_t slotCount = 16;
constexpr uint8_t invalidCbor = 0x12;
constexpr uint8_t missingParameter = 0x14;
constexpr uint8_t denied = 0x27;
constexpr uint8_t unsupportedAlgorithm = 0x26;
constexpr uint8_t storageFull = 0x28;
constexpr uint8_t noCredentials = 0x2e;
constexpr uint8_t internalError = 0x7f;

struct Credential {
    std::array<uint8_t, 32> rpHash;
    std::array<uint8_t, 32> id;
    std::array<uint8_t, 32> secret;
    std::array<uint8_t, 64> user;
    uint8_t userLength;
    uint8_t discoverable;
};

nvs_handle_t store;
Ctaphid transport(PasskeyUsb::send);
std::array<uint8_t, 1024> response;

bool integerField(const CborValue& map, int key, CborValue& value) {
    if (!cbor_value_is_map(&map) || cbor_value_enter_container(&map, &value)) {
        return false;
    }
    while (!cbor_value_at_end(&value)) {
        int current;
        if (!cbor_value_is_integer(&value) || cbor_value_get_int_checked(&value, &current) ||
            cbor_value_advance(&value) || cbor_value_at_end(&value)) {
            return false;
        }
        if (current == key) {
            return true;
        }
        if (cbor_value_advance(&value)) {
            return false;
        }
    }
    return false;
}

bool textField(const CborValue& map, const char* key, CborValue& value) {
    return cbor_value_is_map(&map) && !cbor_value_map_find_value(&map, key, &value) &&
           cbor_value_is_valid(&value);
}

bool getBytes(CborValue value, uint8_t* data, size_t& size) {
    return cbor_value_is_byte_string(&value) &&
           !cbor_value_copy_byte_string(&value, data, &size, nullptr);
}

void text(CborEncoder& encoder, const char* data) {
    cbor_encode_text_stringz(&encoder, data);
}

void bytes(CborEncoder& encoder, Bytes data) {
    cbor_encode_byte_string(&encoder, data.data(), data.size());
}

void slotName(size_t slot, char (&name)[8]) {
    snprintf(name, sizeof(name), "key%02u", static_cast<unsigned>(slot));
}

esp_err_t load(size_t slot, Credential& entry) {
    char name[8];
    slotName(slot, name);
    size_t size = sizeof(entry);
    const auto result = nvs_get_blob(store, name, &entry, &size);
    if (result == ESP_OK && (size != sizeof(entry) || entry.userLength > entry.user.size())) {
        return ESP_ERR_INVALID_SIZE;
    }
    return result;
}

bool listed(const CborValue& list, const Credential& entry) {
    CborValue item;
    if (!cbor_value_is_array(&list) || cbor_value_enter_container(&list, &item)) {
        return false;
    }
    while (!cbor_value_at_end(&item)) {
        CborValue id;
        std::array<uint8_t, 32> candidate;
        size_t size = candidate.size();
        if (textField(item, "id", id) && getBytes(id, candidate.data(), size) &&
            size == candidate.size() && candidate == entry.id) {
            return true;
        }
        if (cbor_value_advance(&item)) {
            break;
        }
    }
    return false;
}

bool supportsEs256(const CborValue& parameters) {
    CborValue item;
    if (!cbor_value_is_array(&parameters) || cbor_value_enter_container(&parameters, &item)) {
        return false;
    }
    while (!cbor_value_at_end(&item)) {
        CborValue alg, type;
        int number;
        bool publicKey;
        if (textField(item, "type", type) && cbor_value_is_text_string(&type) &&
            !cbor_value_text_string_equals(&type, "public-key", &publicKey) && publicKey &&
            textField(item, "alg", alg) && cbor_value_is_integer(&alg) &&
            !cbor_value_get_int_checked(&alg, &number) && number == -7) {
            return true;
        }
        if (cbor_value_advance(&item)) {
            break;
        }
    }
    return false;
}

bool waitForTap() {
    const auto ticket = passkeyGate.beginRequest();
    if (!ticket) {
        return false;
    }
    int64_t nextKeepalive = 0;
    while (!transport.cancelled()) {
        PasskeyUsb::Report packet;
        const auto now = esp_timer_get_time();
        if (PasskeyUsb::receive(packet)) {
            transport.receive(packet, uint32_t(now / 1000));
        }
        if (transport.cancelled()) {
            break;
        }
        if (passkeyGate.consumeApproval(ticket)) {
            return true;
        }
        if (passkeyGate.pendingRequest() != ticket) {
            break;
        }
        if (now >= nextKeepalive) {
            transport.keepalive(2);
            nextKeepalive = now + 90'000;
        }
        vTaskDelay(1);
    }
    passkeyGate.cancel(ticket);
    return false;
}

psa_key_attributes_t keyAttributes() {
    auto attributes = psa_key_attributes_init();
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    return attributes;
}

bool hash(Bytes data, std::array<uint8_t, 32>& result) {
    size_t size;
    return psa_hash_compute(PSA_ALG_SHA_256, data.data(), data.size(), result.data(),
                            result.size(), &size) == PSA_SUCCESS && size == result.size();
}

size_t encodeDerInteger(uint8_t* destination, Bytes value) {
    while (value.size() > 1 && value.front() == 0) {
        value = value.subspan(1);
    }
    const bool pad = (value.front() & 0x80) != 0;
    destination[0] = 2;
    destination[1] = value.size() + pad;
    if (pad) {
        destination[2] = 0;
    }
    std::copy(value.begin(), value.end(), destination + 2 + pad);
    return 2 + destination[1];
}

uint8_t getInfo(CborEncoder& encoder) {
    CborEncoder map, versions, options, transports;
    cbor_encoder_create_map(&encoder, &map, 5);
    cbor_encode_uint(&map, 1);
    cbor_encoder_create_array(&map, &versions, 1);
    text(versions, "FIDO_2_0");
    cbor_encoder_close_container(&map, &versions);
    cbor_encode_uint(&map, 3);
    bytes(map, std::array<uint8_t, 16>{});
    cbor_encode_uint(&map, 4);
    cbor_encoder_create_map(&map, &options, 2);
    text(options, "rk");
    cbor_encode_boolean(&options, true);
    text(options, "up");
    cbor_encode_boolean(&options, true);
    cbor_encoder_close_container(&map, &options);
    cbor_encode_uint(&map, 5);
    cbor_encode_uint(&map, 1200);
    cbor_encode_uint(&map, 9);
    cbor_encoder_create_array(&map, &transports, 1);
    text(transports, "usb");
    cbor_encoder_close_container(&map, &transports);
    return cbor_encoder_close_container_checked(&encoder, &map) ? internalError : 0;
}

uint8_t makeCredential(const CborValue& request, Credential& entry, CborEncoder& encoder) {
    CborValue user, id, parameters, exclusions, options, flag;
    size_t userSize = entry.user.size();
    if (!integerField(request, 3, user) || !textField(user, "id", id) ||
        !getBytes(id, entry.user.data(), userSize) || userSize == 0 ||
        !integerField(request, 4, parameters)) {
        return missingParameter;
    }
    if (!supportsEs256(parameters)) {
        return unsupportedAlgorithm;
    }
    entry.userLength = userSize;
    bool discoverable = false;
    if (integerField(request, 7, options) && textField(options, "rk", flag) &&
        (!cbor_value_is_boolean(&flag) || cbor_value_get_boolean(&flag, &discoverable))) {
        return invalidCbor;
    }
    entry.discoverable = discoverable;
    const bool hasExclusions = integerField(request, 5, exclusions);
    bool excluded = false;
    size_t freeSlot = slotCount;
    for (size_t slot = 0; slot < slotCount; ++slot) {
        Credential existing{};
        const auto status = load(slot, existing);
        if (status == ESP_ERR_NVS_NOT_FOUND) {
            freeSlot = std::min(freeSlot, slot);
        } else if (status != ESP_OK) {
            return internalError;
        } else if (existing.rpHash == entry.rpHash && hasExclusions && listed(exclusions, existing)) {
            excluded = true;
        }
    }
    if (!waitForTap()) {
        return denied;
    }
    if (excluded) {
        return 0x19;
    }
    if (freeSlot == slotCount) {
        return storageFull;
    }

    const auto attributes = keyAttributes();
    mbedtls_svc_key_id_t key{};
    if (psa_generate_key(&attributes, &key) != PSA_SUCCESS) {
        return internalError;
    }
    std::array<uint8_t, 65> point;
    size_t pointLength, secretLength;
    const bool exported = psa_export_public_key(key, point.data(), point.size(), &pointLength) == PSA_SUCCESS &&
        pointLength == point.size() && point.front() == 4 &&
        psa_export_key(key, entry.secret.data(), entry.secret.size(), &secretLength) == PSA_SUCCESS &&
        secretLength == entry.secret.size();
    psa_destroy_key(key);
    if (!exported) {
        return internalError;
    }
    esp_fill_random(entry.id.data(), entry.id.size());

    std::array<uint8_t, 180> auth{};
    std::copy(entry.rpHash.begin(), entry.rpHash.end(), auth.begin());
    auth[32] = 0x41; // User present, with attested credential data
    auth[54] = entry.id.size();
    std::copy(entry.id.begin(), entry.id.end(), auth.begin() + 55);
    constexpr size_t coseOffset = 87;
    CborEncoder cose, fields;
    cbor_encoder_init(&cose, auth.data() + coseOffset, auth.size() - coseOffset, 0);
    cbor_encoder_create_map(&cose, &fields, 5);
    cbor_encode_int(&fields, 1); cbor_encode_int(&fields, 2);
    cbor_encode_int(&fields, 3); cbor_encode_int(&fields, -7);
    cbor_encode_int(&fields, -1); cbor_encode_int(&fields, 1);
    cbor_encode_int(&fields, -2); bytes(fields, {point.data() + 1, 32});
    cbor_encode_int(&fields, -3); bytes(fields, {point.data() + 33, 32});
    if (cbor_encoder_close_container_checked(&cose, &fields)) {
        return internalError;
    }
    CborEncoder map, statement;
    cbor_encoder_create_map(&encoder, &map, 3);
    cbor_encode_uint(&map, 1);
    text(map, "none");
    cbor_encode_uint(&map, 2);
    bytes(map, {auth.data(), coseOffset + cbor_encoder_get_buffer_size(&cose, auth.data() + coseOffset)});
    cbor_encode_uint(&map, 3);
    cbor_encoder_create_map(&map, &statement, 0);
    cbor_encoder_close_container(&map, &statement);
    if (cbor_encoder_close_container_checked(&encoder, &map)) {
        return internalError;
    }

    char name[8];
    slotName(freeSlot, name);
    return nvs_set_blob(store, name, &entry, sizeof(entry)) == ESP_OK &&
           nvs_commit(store) == ESP_OK ? 0 : internalError;
}

uint8_t getAssertion(const CborValue& request, Credential& entry, Bytes clientHash, CborEncoder& encoder) {
    CborValue allowed;
    const bool hasList = integerField(request, 3, allowed);
    const auto rpHash = entry.rpHash;
    bool found = false;
    for (size_t slot = 0; slot < slotCount; ++slot) {
        const auto status = load(slot, entry);
        if (status == ESP_ERR_NVS_NOT_FOUND) {
            continue;
        }
        if (status != ESP_OK) {
            return internalError;
        }
        if (entry.rpHash == rpHash && (hasList ? listed(allowed, entry) : entry.discoverable)) {
            found = true;
            break;
        }
    }
    if (!waitForTap()) {
        return denied;
    }
    if (!found) {
        return noCredentials;
    }

    std::array<uint8_t, 69> signedData{};
    std::copy(rpHash.begin(), rpHash.end(), signedData.begin());
    signedData[32] = 0x01;
    std::copy(clientHash.begin(), clientHash.end(), signedData.begin() + 37);
    std::array<uint8_t, 32> digest;
    if (!hash(signedData, digest)) {
        return internalError;
    }

    auto attributes = keyAttributes();
    mbedtls_svc_key_id_t key{};
    if (psa_import_key(&attributes, entry.secret.data(), entry.secret.size(), &key) != PSA_SUCCESS) {
        return internalError;
    }
    std::array<uint8_t, 64> signature;
    size_t signatureSize;
    const auto status = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest.data(), digest.size(),
                                      signature.data(), signature.size(), &signatureSize);
    psa_destroy_key(key);
    if (status != PSA_SUCCESS || signatureSize != signature.size()) {
        return internalError;
    }
    std::array<uint8_t, 72> der;
    der[0] = 0x30;
    const auto rSize = encodeDerInteger(der.data() + 2, {signature.data(), 32});
    der[1] = rSize + encodeDerInteger(der.data() + 2 + rSize, {signature.data() + 32, 32});

    CborEncoder map, descriptor, user;
    cbor_encoder_create_map(&encoder, &map, hasList ? 3 : 4);
    cbor_encode_uint(&map, 1);
    cbor_encoder_create_map(&map, &descriptor, 2);
    text(descriptor, "id"); bytes(descriptor, entry.id);
    text(descriptor, "type"); text(descriptor, "public-key");
    cbor_encoder_close_container(&map, &descriptor);
    cbor_encode_uint(&map, 2);
    bytes(map, {signedData.data(), 37});
    cbor_encode_uint(&map, 3);
    bytes(map, {der.data(), size_t(2 + der[1])});
    if (!hasList) {
        cbor_encode_uint(&map, 4);
        cbor_encoder_create_map(&map, &user, 1);
        text(user, "id"); bytes(user, {entry.user.data(), entry.userLength});
        cbor_encoder_close_container(&map, &user);
    }
    return cbor_encoder_close_container_checked(&encoder, &map) ? internalError : 0;
}

uint8_t process(Bytes message, CborEncoder& encoder) {
    const uint8_t opcode = message.front();
    if (opcode == 4) {
        return message.size() == 1 ? getInfo(encoder) : invalidCbor;
    }
    if (opcode != 1 && opcode != 2) {
        return 1;
    }
    if (message.size() > 1200) {
        return 0x39;
    }

    CborParser parser;
    CborValue request, rp, rpId, client, options, uv, pin;
    if (cbor_parser_init(message.data() + 1, message.size() - 1, 0, &parser, &request) ||
        !cbor_value_is_map(&request) || cbor_value_validate(&request, CborValidateCanonicalFormat)) {
        return invalidCbor;
    }
    const bool registration = opcode == 1;
    if (integerField(request, registration ? 8 : 6, pin)) {
        return 0x2b;
    }
    if (integerField(request, registration ? 7 : 5, options) && textField(options, "uv", uv)) {
        bool required;
        if (!cbor_value_is_boolean(&uv) || cbor_value_get_boolean(&uv, &required) || required) {
            return 0x2b;
        }
    }
    if (!integerField(request, registration ? 2 : 1, rp)) {
        return missingParameter;
    }
    if (registration) {
        if (!textField(rp, "id", rpId)) {
            return missingParameter;
        }
    } else {
        rpId = rp;
    }
    std::array<uint8_t, 32> clientHash;
    size_t clientLength = clientHash.size();
    char rpName[254];
    size_t rpLength = sizeof(rpName);
    if (!cbor_value_is_text_string(&rpId) ||
        cbor_value_copy_text_string(&rpId, rpName, &rpLength, nullptr) ||
        rpLength == 0 || rpLength > 253 ||
        !integerField(request, registration ? 1 : 2, client) ||
        !getBytes(client, clientHash.data(), clientLength) || clientLength != clientHash.size()) {
        return invalidCbor;
    }

    Credential entry{};
    if (!hash({reinterpret_cast<const uint8_t*>(rpName), rpLength}, entry.rpHash)) {
        return internalError;
    }
    const auto status = registration ? makeCredential(request, entry, encoder)
                                     : getAssertion(request, entry, clientHash, encoder);
    auto* secret = static_cast<volatile uint8_t*>(entry.secret.data());
    for (size_t i = 0; i < entry.secret.size(); ++i) {
        secret[i] = 0;
    }
    return status;
}

void run(void*) {
    for (;;) {
        PasskeyUsb::Report packet;
        const auto now = uint32_t(esp_timer_get_time() / 1000);
        transport.tick(now);
        if (PasskeyUsb::receive(packet)) {
            const auto request = transport.receive(packet, now);
            if (!request.empty()) {
                CborEncoder encoder;
                cbor_encoder_init(&encoder, response.data() + 1, response.size() - 1, 0);
                response[0] = process(request, encoder);
                const auto length = response[0] ? 1 :
                    1 + cbor_encoder_get_buffer_size(&encoder, response.data() + 1);
                transport.finish({response.data(), length});
            }
        } else {
            vTaskDelay(1);
        }
    }
}
}

bool PasskeyAuthenticator::begin() {
    if (psa_crypto_init() != PSA_SUCCESS || nvs_open("passkey", NVS_READWRITE, &store) != ESP_OK) {
        return false;
    }
    if (!PasskeyUsb::begin() || xTaskCreate(run, "passkey", 12288, nullptr, 4, nullptr) != pdPASS) {
        nvs_close(store);
        return false;
    }
    return true;
}
