#ifndef SECUREVAULT_PASSWORDENTRY_H
#define SECUREVAULT_PASSWORDENTRY_H

#include <iostream>
#include <memory>
#include <string>

class PasswordEntry {
private:
    static int activeCount_;

protected:
    std::string id_;
    std::string service_;
    std::string username_;
    std::string password_;
    std::string category_;
    std::string notes_;

public:
    PasswordEntry();
    PasswordEntry(std::string id, std::string service, std::string username, std::string password);
    PasswordEntry(std::string id, std::string service, std::string username, std::string password,
                  std::string category, std::string notes);
    PasswordEntry(const PasswordEntry& other);
    PasswordEntry& operator=(const PasswordEntry& other);
    virtual ~PasswordEntry();

    inline const std::string& id() const { return id_; }
    inline const std::string& service() const { return service_; }
    inline const std::string& username() const { return username_; }
    inline const std::string& password() const { return password_; }
    inline const std::string& category() const { return category_; }
    inline const std::string& notes() const { return notes_; }

    void updateField(const std::string& field, const std::string& value);
    void updateField(const std::string& service, const std::string& username,
                     const std::string& password, const std::string& category,
                     const std::string& notes);

    virtual std::string typeName() const = 0;
    virtual std::string summary() const;
    virtual std::unique_ptr<PasswordEntry> clone() const = 0;

    bool operator==(const PasswordEntry& other) const;
    bool operator<(const PasswordEntry& other) const;

    static int activeCount();

    // Friend output keeps password private while allowing summary access to private fields.
    friend std::ostream& operator<<(std::ostream& os, const PasswordEntry& entry);
};

class WebsiteCredential : public PasswordEntry {
public:
    WebsiteCredential();
    WebsiteCredential(std::string id, std::string service, std::string username, std::string password);
    WebsiteCredential(std::string id, std::string service, std::string username,
                      std::string password, std::string category, std::string notes);
    WebsiteCredential(const WebsiteCredential& other);
    ~WebsiteCredential() override;

    std::string typeName() const override;
    std::string summary() const override;
    std::unique_ptr<PasswordEntry> clone() const override;
};

class ApplicationCredential : public PasswordEntry {
public:
    ApplicationCredential();
    ApplicationCredential(std::string id, std::string service, std::string username,
                          std::string password, std::string category, std::string notes);
    ApplicationCredential(const ApplicationCredential& other);
    ~ApplicationCredential() override;

    std::string typeName() const override;
    std::string summary() const override;
    std::unique_ptr<PasswordEntry> clone() const override;
};

#endif
