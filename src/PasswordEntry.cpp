#include "PasswordEntry.h"

#include <sstream>
#include <utility>

int PasswordEntry::activeCount_ = 0;

PasswordEntry::PasswordEntry() {
    ++activeCount_;
}

PasswordEntry::PasswordEntry(std::string id, std::string service, std::string username, std::string password)
    : id_(std::move(id)), service_(std::move(service)), username_(std::move(username)),
      password_(std::move(password)) {
    ++activeCount_;
}

PasswordEntry::PasswordEntry(std::string id, std::string service, std::string username, std::string password,
                             std::string category, std::string notes)
    : id_(std::move(id)), service_(std::move(service)), username_(std::move(username)),
      password_(std::move(password)), category_(std::move(category)), notes_(std::move(notes)) {
    ++activeCount_;
}

PasswordEntry::PasswordEntry(const PasswordEntry& other)
    : id_(other.id_), service_(other.service_), username_(other.username_),
      password_(other.password_), category_(other.category_), notes_(other.notes_) {
    ++activeCount_;
}

PasswordEntry& PasswordEntry::operator=(const PasswordEntry& other) {
    if (this != &other) {
        this->id_ = other.id_;
        this->service_ = other.service_;
        this->username_ = other.username_;
        this->password_ = other.password_;
        this->category_ = other.category_;
        this->notes_ = other.notes_;
    }
    return *this;
}

PasswordEntry::~PasswordEntry() {
    --activeCount_;
}

void PasswordEntry::updateField(const std::string& field, const std::string& value) {
    if (field == "service") this->service_ = value;
    else if (field == "username") this->username_ = value;
    else if (field == "password") this->password_ = value;
    else if (field == "category") this->category_ = value;
    else if (field == "notes") this->notes_ = value;
}

void PasswordEntry::updateField(const std::string& service, const std::string& username,
                                const std::string& password, const std::string& category,
                                const std::string& notes) {
    if (!service.empty()) this->service_ = service;
    if (!username.empty()) this->username_ = username;
    if (!password.empty()) this->password_ = password;
    if (!category.empty()) this->category_ = category;
    if (!notes.empty()) this->notes_ = notes;
}

std::string PasswordEntry::summary() const {
    std::ostringstream out;
    out << "[" << id_ << "] " << service_ << " | " << username_;
    if (!category_.empty()) out << " | " << category_;
    return out.str();
}

bool PasswordEntry::operator==(const PasswordEntry& other) const {
    return id_ == other.id_;
}

bool PasswordEntry::operator<(const PasswordEntry& other) const {
    return service_ < other.service_;
}

int PasswordEntry::activeCount() {
    return activeCount_;
}

std::ostream& operator<<(std::ostream& os, const PasswordEntry& entry) {
    os << entry.summary();
    return os;
}

WebsiteCredential::WebsiteCredential() = default;

WebsiteCredential::WebsiteCredential(std::string id, std::string service, std::string username, std::string password)
    : PasswordEntry(std::move(id), std::move(service), std::move(username), std::move(password)) {}

WebsiteCredential::WebsiteCredential(std::string id, std::string service, std::string username,
                                     std::string password, std::string category, std::string notes)
    : PasswordEntry(std::move(id), std::move(service), std::move(username), std::move(password),
                    std::move(category), std::move(notes)) {}

WebsiteCredential::WebsiteCredential(const WebsiteCredential& other) : PasswordEntry(other) {}
WebsiteCredential::~WebsiteCredential() = default;

std::string WebsiteCredential::typeName() const {
    return "Website";
}

std::string WebsiteCredential::summary() const {
    return "Web " + PasswordEntry::summary();
}

std::unique_ptr<PasswordEntry> WebsiteCredential::clone() const {
    return std::make_unique<WebsiteCredential>(*this);
}

ApplicationCredential::ApplicationCredential() = default;

ApplicationCredential::ApplicationCredential(std::string id, std::string service, std::string username,
                                             std::string password, std::string category, std::string notes)
    : PasswordEntry(std::move(id), std::move(service), std::move(username), std::move(password),
                    std::move(category), std::move(notes)) {}

ApplicationCredential::ApplicationCredential(const ApplicationCredential& other) : PasswordEntry(other) {}
ApplicationCredential::~ApplicationCredential() = default;

std::string ApplicationCredential::typeName() const {
    return "Application";
}

std::string ApplicationCredential::summary() const {
    return "App " + PasswordEntry::summary();
}

std::unique_ptr<PasswordEntry> ApplicationCredential::clone() const {
    return std::make_unique<ApplicationCredential>(*this);
}
