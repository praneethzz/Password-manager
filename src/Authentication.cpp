#include "Authentication.h"

#include <cctype>

Authentication::Authentication(StorageManager& storage) : storage_(storage) {}

bool Authentication::isInitialized() const {
    return storage_.exists();
}

bool Authentication::setup(const std::string& masterPassword, const std::string& confirmation) {
    if (masterPassword != confirmation) return false;
    if (evaluateStrength(masterPassword) == PasswordRating::Weak) return false;
    storage_.initializeEmpty(masterPassword);
    authenticated_ = true;
    return true;
}

bool Authentication::login(const std::string& masterPassword) {
    authenticated_ = storage_.verifyMasterPassword(masterPassword);
    return authenticated_;
}

void Authentication::logout() {
    authenticated_ = false;
}

bool Authentication::isAuthenticated() const {
    return authenticated_;
}

bool Authentication::changeMasterPassword(const std::string& currentPassword, const std::string& newPassword,
                                          const std::string& confirmation) {
    if (!authenticated_ || newPassword != confirmation) return false;
    if (evaluateStrength(newPassword) == PasswordRating::Weak) return false;
    storage_.changeMasterPassword(currentPassword, newPassword);
    return true;
}

PasswordRating Authentication::evaluateStrength(const std::string& password, std::vector<std::string>* feedback) {
    int score = 0;
    bool upper = false, lower = false, digit = false, symbol = false;
    for (unsigned char c : password) {
        upper = upper || std::isupper(c);
        lower = lower || std::islower(c);
        digit = digit || std::isdigit(c);
        symbol = symbol || std::ispunct(c);
    }
    if (password.size() >= 12) score += 2;
    else if (password.size() >= 8) score += 1;
    if (upper) ++score;
    if (lower) ++score;
    if (digit) ++score;
    if (symbol) ++score;

    if (feedback) {
        if (password.size() < 12) feedback->push_back("Use at least 12 characters.");
        if (!upper) feedback->push_back("Add uppercase letters.");
        if (!lower) feedback->push_back("Add lowercase letters.");
        if (!digit) feedback->push_back("Add digits.");
        if (!symbol) feedback->push_back("Add symbols.");
        if (feedback->empty()) feedback->push_back("Password has a strong mix of length and character classes.");
    }

    if (score >= 6) return PasswordRating::Strong;
    if (score >= 4) return PasswordRating::Fair;
    return PasswordRating::Weak;
}

std::string Authentication::ratingName(PasswordRating rating) {
    switch (rating) {
        case PasswordRating::Strong: return "Strong";
        case PasswordRating::Fair: return "Fair";
        default: return "Weak";
    }
}
