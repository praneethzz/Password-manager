#ifndef SECUREVAULT_PASSWORDMANAGER_H
#define SECUREVAULT_PASSWORDMANAGER_H

#include "PasswordEntry.h"

#include <memory>
#include <string>
#include <vector>

class PasswordManager {
private:
    std::vector<std::unique_ptr<PasswordEntry>> entries_;

    const PasswordEntry* searchRecursiveByService(const std::string& needle, std::size_t index) const;

public:
    PasswordManager() = default;
    explicit PasswordManager(std::vector<std::unique_ptr<PasswordEntry>> entries);
    PasswordManager(const PasswordManager& other);
    PasswordManager& operator=(const PasswordManager& other);
    ~PasswordManager();

    void add(std::unique_ptr<PasswordEntry> entry);
    bool removeById(const std::string& id);
    PasswordEntry* findById(const std::string& id);
    const PasswordEntry* findById(const std::string& id) const;
    std::vector<const PasswordEntry*> searchByService(const std::string& service) const;
    std::vector<const PasswordEntry*> searchByUsername(const std::string& username) const;
    const PasswordEntry* searchByServiceRecursive(const std::string& service) const;
    bool hasDuplicate(const std::string& service, const std::string& username) const;
    void sortByService();
    std::size_t count() const;
    bool empty() const;
    const std::vector<std::unique_ptr<PasswordEntry>>& entries() const;
};

template <typename T>
const T* firstOrNull(const std::vector<T*>& values) {
    return values.empty() ? nullptr : values.front();
}

#endif
