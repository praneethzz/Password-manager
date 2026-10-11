#ifndef SECUREVAULT_PASSWORDGENERATOR_H
#define SECUREVAULT_PASSWORDGENERATOR_H

#include "EncryptionService.h"

#include <string>

struct PasswordGeneratorOptions {
    int length = 16;
    bool uppercase = true;
    bool lowercase = true;
    bool digits = true;
    bool symbols = true;
};

class PasswordGenerator {
private:
    EncryptionService crypto_;
    char pick(const std::string& chars) const;

public:
    std::string generate(const PasswordGeneratorOptions& options) const;
};

#endif
