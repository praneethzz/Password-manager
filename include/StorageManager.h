#ifndef SECUREVAULT_STORAGEMANAGER_H
#define SECUREVAULT_STORAGEMANAGER_H

#include "EncryptionService.h"
#include "PasswordEntry.h"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <vector>

class StorageException : public std::runtime_error {
public:
    explicit StorageException(const std::string& message) : std::runtime_error(message) {}
};

class StorageManager {
private:
    std::filesystem::path filePath_;
    EncryptionService crypto_;

    static void appendUInt32(std::vector<unsigned char>& out, std::uint32_t value);
    static std::uint32_t readUInt32(const std::vector<unsigned char>& data, std::size_t& offset);
    static void appendString(std::vector<unsigned char>& out, const std::string& value);
    static std::string readString(const std::vector<unsigned char>& data, std::size_t& offset);

public:
    explicit StorageManager(std::filesystem::path filePath);

    bool exists() const;
    const std::filesystem::path& path() const;

    void initializeEmpty(const std::string& masterPassword);
    void save(const std::vector<std::unique_ptr<PasswordEntry>>& entries,
              const std::string& masterPassword);
    std::vector<std::unique_ptr<PasswordEntry>> load(const std::string& masterPassword) const;
    bool verifyMasterPassword(const std::string& masterPassword) const;
    void changeMasterPassword(const std::string& oldPassword, const std::string& newPassword);

    static std::vector<unsigned char> serialize(const std::vector<std::unique_ptr<PasswordEntry>>& entries);
    static std::vector<std::unique_ptr<PasswordEntry>> deserialize(const std::vector<unsigned char>& data);
    static std::string generateId();
};

#endif
