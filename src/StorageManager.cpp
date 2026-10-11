#include "StorageManager.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace {
constexpr const char* VaultMagic = "SECUREVAULT1";
constexpr const char* PayloadMagic = "PVLT1";

std::string trimCr(const std::string& value) {
    if (!value.empty() && value.back() == '\r') return value.substr(0, value.size() - 1);
    return value;
}

EncryptedBlob readBlob(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) throw StorageException("Vault file cannot be opened");

    std::string line;
    std::getline(in, line);
    if (trimCr(line) != VaultMagic) throw StorageException("Vault file format is invalid");

    EncryptedBlob blob;
    while (std::getline(in, line)) {
        line = trimCr(line);
        auto pos = line.find('=');
        if (pos == std::string::npos) throw StorageException("Vault metadata is invalid");
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        if (key == "iterations") blob.iterations = std::stoul(value);
        else if (key == "salt") blob.salt = base64Decode(value);
        else if (key == "nonce") blob.nonce = base64Decode(value);
        else if (key == "ciphertext") blob.ciphertext = base64Decode(value);
        else if (key == "tag") blob.tag = base64Decode(value);
    }

    if (blob.iterations < 100000 || blob.salt.empty() || blob.nonce.empty() ||
        blob.ciphertext.empty() || blob.tag.empty()) {
        throw StorageException("Vault file is incomplete or corrupted");
    }
    return blob;
}

void writeBlob(const std::filesystem::path& path, const EncryptedBlob& blob) {
    std::filesystem::create_directories(path.parent_path());
    auto temp = path;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::trunc);
        if (!out) throw StorageException("Temporary vault file cannot be written");
        out << VaultMagic << "\n";
        out << "iterations=" << blob.iterations << "\n";
        out << "salt=" << base64Encode(blob.salt) << "\n";
        out << "nonce=" << base64Encode(blob.nonce) << "\n";
        out << "ciphertext=" << base64Encode(blob.ciphertext) << "\n";
        out << "tag=" << base64Encode(blob.tag) << "\n";
        if (!out) throw StorageException("Failed while writing vault data");
    }
    std::filesystem::rename(temp, path);
}
}

StorageManager::StorageManager(std::filesystem::path filePath) : filePath_(std::move(filePath)) {}

bool StorageManager::exists() const {
    return std::filesystem::exists(filePath_);
}

const std::filesystem::path& StorageManager::path() const {
    return filePath_;
}

void StorageManager::initializeEmpty(const std::string& masterPassword) {
    std::vector<std::unique_ptr<PasswordEntry>> empty;
    save(empty, masterPassword);
}

void StorageManager::save(const std::vector<std::unique_ptr<PasswordEntry>>& entries,
                          const std::string& masterPassword) {
    auto data = serialize(entries);
    auto blob = crypto_.encrypt(data, masterPassword);
    writeBlob(filePath_, blob);
    std::fill(data.begin(), data.end(), 0);
}

std::vector<std::unique_ptr<PasswordEntry>> StorageManager::load(const std::string& masterPassword) const {
    auto blob = readBlob(filePath_);
    auto plaintext = crypto_.decrypt(blob, masterPassword);
    auto entries = deserialize(plaintext);
    std::fill(plaintext.begin(), plaintext.end(), 0);
    return entries;
}

bool StorageManager::verifyMasterPassword(const std::string& masterPassword) const {
    try {
        (void)load(masterPassword);
        return true;
    } catch (...) {
        return false;
    }
}

void StorageManager::changeMasterPassword(const std::string& oldPassword, const std::string& newPassword) {
    auto entries = load(oldPassword);
    save(entries, newPassword);
}

void StorageManager::appendUInt32(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>(value & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xFF));
}

std::uint32_t StorageManager::readUInt32(const std::vector<unsigned char>& data, std::size_t& offset) {
    if (offset + 4 > data.size()) throw StorageException("Payload ended unexpectedly");
    std::uint32_t value = static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
}

void StorageManager::appendString(std::vector<unsigned char>& out, const std::string& value) {
    if (value.size() > 1000000) throw StorageException("Field is too large");
    appendUInt32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::string StorageManager::readString(const std::vector<unsigned char>& data, std::size_t& offset) {
    std::uint32_t size = readUInt32(data, offset);
    if (offset + size > data.size()) throw StorageException("Payload field is invalid");
    std::string value(data.begin() + static_cast<std::ptrdiff_t>(offset),
                      data.begin() + static_cast<std::ptrdiff_t>(offset + size));
    offset += size;
    return value;
}

std::vector<unsigned char> StorageManager::serialize(const std::vector<std::unique_ptr<PasswordEntry>>& entries) {
    std::vector<unsigned char> out;
    out.insert(out.end(), PayloadMagic, PayloadMagic + 5);
    appendUInt32(out, static_cast<std::uint32_t>(entries.size()));
    for (const auto& entry : entries) {
        out.push_back(entry->typeName() == "Application" ? 2 : 1);
        appendString(out, entry->id());
        appendString(out, entry->service());
        appendString(out, entry->username());
        appendString(out, entry->password());
        appendString(out, entry->category());
        appendString(out, entry->notes());
    }
    return out;
}

std::vector<std::unique_ptr<PasswordEntry>> StorageManager::deserialize(const std::vector<unsigned char>& data) {
    if (data.size() < 9 || std::string(data.begin(), data.begin() + 5) != PayloadMagic) {
        throw StorageException("Decrypted payload format is invalid");
    }
    std::size_t offset = 5;
    std::uint32_t count = readUInt32(data, offset);
    if (count > 10000) throw StorageException("Payload contains too many records");

    std::vector<std::unique_ptr<PasswordEntry>> entries;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (offset >= data.size()) throw StorageException("Record type is missing");
        unsigned char type = data[offset++];
        std::string id = readString(data, offset);
        std::string service = readString(data, offset);
        std::string username = readString(data, offset);
        std::string password = readString(data, offset);
        std::string category = readString(data, offset);
        std::string notes = readString(data, offset);
        if (id.empty() || service.empty() || username.empty()) {
            throw StorageException("A stored credential is missing required fields");
        }
        if (type == 2) {
            entries.push_back(std::make_unique<ApplicationCredential>(id, service, username, password, category, notes));
        } else if (type == 1) {
            entries.push_back(std::make_unique<WebsiteCredential>(id, service, username, password, category, notes));
        } else {
            throw StorageException("Unknown credential type");
        }
    }
    if (offset != data.size()) throw StorageException("Payload contains trailing data");
    return entries;
}

std::string StorageManager::generateId() {
    static EncryptionService crypto;
    auto bytes = crypto.randomBytes(8);
    std::ostringstream out;
    out << "SV-";
    const char* hex = "0123456789ABCDEF";
    for (unsigned char byte : bytes) {
        out << hex[(byte >> 4) & 0x0F] << hex[byte & 0x0F];
    }
    return out.str();
}
