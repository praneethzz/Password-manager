#ifndef SECUREVAULT_AUTHENTICATION_H
#define SECUREVAULT_AUTHENTICATION_H

#include "StorageManager.h"

#include <string>
#include <vector>

enum class PasswordRating {
    Weak,
    Fair,
    Strong
};

class Authentication {
private:
    StorageManager& storage_;
    bool authenticated_ = false;

public:
    explicit Authentication(StorageManager& storage);
    bool isInitialized() const;
    bool setup(const std::string& masterPassword, const std::string& confirmation);
    bool login(const std::string& masterPassword);
    void logout();
    bool isAuthenticated() const;
    bool changeMasterPassword(const std::string& currentPassword, const std::string& newPassword,
                              const std::string& confirmation);

    static PasswordRating evaluateStrength(const std::string& password, std::vector<std::string>* feedback = nullptr);
    static std::string ratingName(PasswordRating rating);
};

#endif
