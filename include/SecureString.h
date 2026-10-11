#ifndef SECUREVAULT_SECURESTRING_H
#define SECUREVAULT_SECURESTRING_H

#include <algorithm>
#include <string>

class SecureString {
private:
    std::string value_;

public:
    SecureString() = default;
    explicit SecureString(std::string value) : value_(std::move(value)) {}
    SecureString(const SecureString& other) : value_(other.value_) {}
    SecureString& operator=(const SecureString& other) {
        if (this != &other) {
            clear();
            value_ = other.value_;
        }
        return *this;
    }
    ~SecureString() { clear(); }

    const std::string& str() const { return value_; }
    std::string& str() { return value_; }
    bool empty() const { return value_.empty(); }

    void clear() {
        volatile char* p = value_.empty() ? nullptr : &value_[0];
        for (std::size_t i = 0; i < value_.size(); ++i) {
            p[i] = 0;
        }
        value_.clear();
    }
};

#endif
