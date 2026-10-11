#include "PasswordManager.h"

#include <algorithm>

namespace {
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool containsCaseInsensitive(const std::string& value, const std::string& needle) {
    return lower(value).find(lower(needle)) != std::string::npos;
}
}

PasswordManager::PasswordManager(std::vector<std::unique_ptr<PasswordEntry>> entries)
    : entries_(std::move(entries)) {}

PasswordManager::PasswordManager(const PasswordManager& other) {
    for (const auto& entry : other.entries_) entries_.push_back(entry->clone());
}

PasswordManager& PasswordManager::operator=(const PasswordManager& other) {
    if (this != &other) {
        entries_.clear();
        for (const auto& entry : other.entries_) entries_.push_back(entry->clone());
    }
    return *this;
}

PasswordManager::~PasswordManager() = default;

void PasswordManager::add(std::unique_ptr<PasswordEntry> entry) {
    entries_.push_back(std::move(entry));
}

bool PasswordManager::removeById(const std::string& id) {
    auto before = entries_.size();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const auto& entry) {
        return entry->id() == id;
    }), entries_.end());
    return entries_.size() != before;
}

PasswordEntry* PasswordManager::findById(const std::string& id) {
    for (auto& entry : entries_) if (entry->id() == id) return entry.get();
    return nullptr;
}

const PasswordEntry* PasswordManager::findById(const std::string& id) const {
    for (const auto& entry : entries_) if (entry->id() == id) return entry.get();
    return nullptr;
}

std::vector<const PasswordEntry*> PasswordManager::searchByService(const std::string& service) const {
    std::vector<const PasswordEntry*> matches;
    for (const auto& entry : entries_) {
        if (containsCaseInsensitive(entry->service(), service)) matches.push_back(entry.get());
    }
    return matches;
}

std::vector<const PasswordEntry*> PasswordManager::searchByUsername(const std::string& username) const {
    std::vector<const PasswordEntry*> matches;
    for (const auto& entry : entries_) {
        if (containsCaseInsensitive(entry->username(), username)) matches.push_back(entry.get());
    }
    return matches;
}

const PasswordEntry* PasswordManager::searchRecursiveByService(const std::string& needle, std::size_t index) const {
    if (index >= entries_.size()) return nullptr;
    if (containsCaseInsensitive(entries_[index]->service(), needle)) return entries_[index].get();
    return searchRecursiveByService(needle, index + 1);
}

const PasswordEntry* PasswordManager::searchByServiceRecursive(const std::string& service) const {
    return searchRecursiveByService(service, 0);
}

bool PasswordManager::hasDuplicate(const std::string& service, const std::string& username) const {
    for (const auto& entry : entries_) {
        if (lower(entry->service()) == lower(service) && lower(entry->username()) == lower(username)) return true;
    }
    return false;
}

void PasswordManager::sortByService() {
    std::sort(entries_.begin(), entries_.end(), [](const auto& a, const auto& b) {
        return *a < *b;
    });
}

std::size_t PasswordManager::count() const {
    return entries_.size();
}

bool PasswordManager::empty() const {
    return entries_.empty();
}

const std::vector<std::unique_ptr<PasswordEntry>>& PasswordManager::entries() const {
    return entries_;
}
