#include "Authentication.h"
#include "PasswordGenerator.h"
#include "PasswordManager.h"
#include "StorageManager.h"

#include <filesystem>
#include <iostream>
#include <limits>

namespace {
std::string line(const std::string& prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    return value;
}

int menuNumber(const std::string& prompt) {
    std::string text = line(prompt);
    try { return std::stoi(text); } catch (...) { return -1; }
}

void printEntries(const PasswordManager& manager) {
    if (manager.empty()) {
        std::cout << "No credentials saved.\n";
        return;
    }
    for (const auto& entry : manager.entries()) std::cout << *entry << "\n";
    std::cout << "Total: " << manager.count() << "\n";
}

PasswordGeneratorOptions askGeneratorOptions() {
    PasswordGeneratorOptions opt;
    opt.length = menuNumber("Length (8-128): ");
    opt.uppercase = line("Include uppercase? (y/n): ") != "n";
    opt.lowercase = line("Include lowercase? (y/n): ") != "n";
    opt.digits = line("Include digits? (y/n): ") != "n";
    opt.symbols = line("Include symbols? (y/n): ") != "n";
    return opt;
}

void saveOrReport(StorageManager& storage, const PasswordManager& manager, const std::string& master) {
    storage.save(manager.entries(), master);
    std::cout << "Changes saved.\n";
}
}

int main() {
    std::filesystem::path vaultPath = std::filesystem::current_path() / "data" / "vault.svlt";
    StorageManager storage(vaultPath);
    Authentication auth(storage);
    std::string masterPassword;

    try {
        std::cout << "SecureVault - local password manager\n";
        if (!auth.isInitialized()) {
            std::cout << "First-time setup.\n";
            while (true) {
                masterPassword = line("Create master password: ");
                std::string confirm = line("Confirm master password: ");
                std::vector<std::string> feedback;
                auto rating = Authentication::evaluateStrength(masterPassword, &feedback);
                std::cout << "Strength: " << Authentication::ratingName(rating) << "\n";
                for (const auto& item : feedback) std::cout << "- " << item << "\n";
                if (auth.setup(masterPassword, confirm)) break;
                std::cout << "Setup failed. Passwords must match and cannot be weak.\n";
            }
        } else {
            for (int attempts = 0; attempts < 3 && !auth.isAuthenticated(); ++attempts) {
                masterPassword = line("Master password: ");
                if (!auth.login(masterPassword)) std::cout << "Authentication failed.\n";
            }
            if (!auth.isAuthenticated()) return 1;
        }

        PasswordManager manager(storage.load(masterPassword));
        PasswordGenerator generator;

        while (auth.isAuthenticated()) {
            std::cout << "\n1 List  2 Add  3 Reveal  4 Search  5 Update  6 Delete\n"
                      << "7 Generate  8 Strength  9 Change master  10 Sort  0 Exit\n";
            int choice = menuNumber("Choose: ");
            if (choice == 0) {
                auth.logout();
                break;
            } else if (choice == 1) {
                printEntries(manager);
            } else if (choice == 2) {
                std::string type = line("Type website/app (w/a): ");
                std::string service = line("Service: ");
                std::string username = line("Username/email: ");
                std::string password = line("Password: ");
                std::string category = line("Category (optional): ");
                std::string notes = line("Notes (optional): ");
                if (service.empty() || username.empty() || password.empty()) {
                    std::cout << "Service, username, and password are required.\n";
                    continue;
                }
                if (manager.hasDuplicate(service, username) &&
                    line("Duplicate detected. Save anyway? (y/n): ") != "y") {
                    std::cout << "Cancelled.\n";
                    continue;
                }
                auto id = StorageManager::generateId();
                if (type == "a") {
                    manager.add(std::make_unique<ApplicationCredential>(id, service, username, password, category, notes));
                } else {
                    manager.add(std::make_unique<WebsiteCredential>(id, service, username, password, category, notes));
                }
                saveOrReport(storage, manager, masterPassword);
            } else if (choice == 3) {
                auto id = line("Entry id: ");
                auto* entry = manager.findById(id);
                if (!entry) std::cout << "No matching entry.\n";
                else if (line("Reveal password? (y/n): ") == "y") std::cout << "Password: " << entry->password() << "\n";
            } else if (choice == 4) {
                int mode = menuNumber("Search by 1 service, 2 username, 3 id: ");
                std::string q = line("Search text: ");
                if (mode == 3) {
                    auto* entry = manager.findById(q);
                    if (entry) std::cout << *entry << "\n"; else std::cout << "No results.\n";
                } else {
                    auto matches = mode == 2 ? manager.searchByUsername(q) : manager.searchByService(q);
                    if (matches.empty()) std::cout << "No results.\n";
                    for (auto* entry : matches) std::cout << *entry << "\n";
                }
            } else if (choice == 5) {
                auto id = line("Entry id to update: ");
                auto* entry = manager.findById(id);
                if (!entry) { std::cout << "No matching entry.\n"; continue; }
                std::cout << "Leave a field blank to keep the existing value.\n";
                entry->updateField(line("Service: "), line("Username/email: "), line("Password: "),
                                   line("Category: "), line("Notes: "));
                saveOrReport(storage, manager, masterPassword);
            } else if (choice == 6) {
                auto id = line("Entry id to delete: ");
                auto* entry = manager.findById(id);
                if (!entry) { std::cout << "No matching entry.\n"; continue; }
                std::cout << *entry << "\n";
                if (line("Delete this entry? (y/n): ") == "y") {
                    manager.removeById(id);
                    saveOrReport(storage, manager, masterPassword);
                } else {
                    std::cout << "Deletion cancelled.\n";
                }
            } else if (choice == 7) {
                try { std::cout << "Generated: " << generator.generate(askGeneratorOptions()) << "\n"; }
                catch (const std::exception& ex) { std::cout << ex.what() << "\n"; }
            } else if (choice == 8) {
                std::vector<std::string> feedback;
                auto rating = Authentication::evaluateStrength(line("Password to evaluate: "), &feedback);
                std::cout << "Strength: " << Authentication::ratingName(rating) << "\n";
                for (const auto& item : feedback) std::cout << "- " << item << "\n";
            } else if (choice == 9) {
                std::string current = line("Current master password: ");
                std::string next = line("New master password: ");
                std::string confirm = line("Confirm new master password: ");
                if (auth.changeMasterPassword(current, next, confirm)) {
                    masterPassword = next;
                    std::cout << "Master password changed and vault re-encrypted.\n";
                } else {
                    std::cout << "Master password change failed.\n";
                }
            } else if (choice == 10) {
                manager.sortByService();
                printEntries(manager);
            } else {
                std::cout << "Invalid menu input.\n";
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "SecureVault error: " << ex.what() << "\n";
        return 1;
    }
    std::cout << "Logged out. Goodbye.\n";
    return 0;
}
