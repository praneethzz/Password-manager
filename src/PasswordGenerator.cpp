#include "PasswordGenerator.h"

#include <algorithm>
#include <stdexcept>

char PasswordGenerator::pick(const std::string& chars) const {
    auto byte = crypto_.randomBytes(1).front();
    return chars[byte % chars.size()];
}

std::string PasswordGenerator::generate(const PasswordGeneratorOptions& options) const {
    if (options.length < 8 || options.length > 128) {
        throw std::invalid_argument("Password length must be between 8 and 128");
    }

    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string digits = "0123456789";
    const std::string symbols = "!@#$%^&*()-_=+[]{};:,.?";

    std::string pool;
    std::string result;
    if (options.uppercase) { pool += upper; result.push_back(pick(upper)); }
    if (options.lowercase) { pool += lower; result.push_back(pick(lower)); }
    if (options.digits) { pool += digits; result.push_back(pick(digits)); }
    if (options.symbols) { pool += symbols; result.push_back(pick(symbols)); }
    if (pool.empty()) throw std::invalid_argument("Select at least one character category");
    if (static_cast<int>(result.size()) > options.length) {
        throw std::invalid_argument("Length is too short for the selected categories");
    }

    while (static_cast<int>(result.size()) < options.length) result.push_back(pick(pool));

    auto random = crypto_.randomBytes(result.size());
    for (std::size_t i = result.size() - 1; i > 0; --i) {
        std::size_t j = random[i] % (i + 1);
        std::swap(result[i], result[j]);
    }
    return result;
}
