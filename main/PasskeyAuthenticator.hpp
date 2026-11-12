#pragma once

#include "cJSON.h"

class PasskeyAuthenticator {
public:
    static bool begin();
    static bool listCredentials(cJSON* array);
};
