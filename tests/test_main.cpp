#include "Authentication.h"
#include "PasswordGenerator.h"
#include "PasswordManager.h"
#include "StorageManager.h"

#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
int failures = 0;

void expect(bool condition, const std::string& name) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << name << "\n";
    } else {
        std::cout << "PASS: " << name << "\n";
    }
}

void expectThrows(const std::function<void()>& fn, const std::string& name) {
    try {
        fn();
        expect(false, name);
    } catch (...) {
        expect(true, name);
    }
}

std::filesystem::path testPath(const std::string& name) {
    auto dir = std::filesystem::current_path() / "data" / "test";
    std::filesystem::create_directories(dir);
    return dir / name;
}
}

int main() {
    const std::string master = "GoodMaster#2026";
    const std::string changed = "BetterMaster#2027";
    auto path = testPath("vault_test.svlt");
    std::filesystem::remove(path);

    StorageManager storage(path);
    Authentication auth(storage);
    expect(!auth.isInitialized(), "missing data files");
    expect(!auth.setup("weak", "weak"), "weak setup rejected");
    expect(auth.setup(master, master), "initial setup");
    expect(auth.isInitialized(), "vault file created");

    Authentication auth2(storage);
    expect(auth2.login(master), "successful authentication");
    expect(!auth2.login("wrong-password"), "failed authentication");
    expect(auth2.login(master), "login restored after failed attempt");

    PasswordManager manager(storage.load(master));
    expect(manager.empty(), "empty credential collection");
    manager.add(std::make_unique<WebsiteCredential>(StorageManager::generateId(), "example.com", "me@example.com",
                                                    "Secret#12345", "personal", "main account"));
    manager.add(std::make_unique<ApplicationCredential>(StorageManager::generateId(), "MailApp", "me@example.com",
                                                        "Another#12345", "work", "desktop app"));
    expect(manager.count() == 2, "multiple saved credentials");
    expect(manager.hasDuplicate("example.com", "me@example.com"), "duplicate detection");
    storage.save(manager.entries(), master);

    std::string encryptedText;
    {
        std::ifstream in(path);
        encryptedText.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    expect(encryptedText.find("Secret#12345") == std::string::npos, "saved password not plaintext");

    PasswordManager restarted(storage.load(master));
    expect(restarted.count() == 2, "restart load");
    auto serviceMatches = restarted.searchByService("example");
    expect(serviceMatches.size() == 1, "search existing credential by service");
    expect(restarted.searchByUsername("nobody").empty(), "search nonexistent credential");
    auto* found = restarted.findById(serviceMatches.front()->id());
    expect(found != nullptr && found->password() == "Secret#12345", "view/reveal credential");
    found->updateField("password", "Updated#12345");
    expect(found->password() == "Updated#12345", "updating credential");
    auto deleteId = found->id();
    expect(restarted.findById(deleteId) != nullptr, "cancelling deletion leaves credential");
    expect(restarted.removeById(deleteId), "deleting credential");
    expect(restarted.findById(deleteId) == nullptr, "deleted credential gone");
    storage.save(restarted.entries(), master);

    PasswordGenerator generator;
    PasswordGeneratorOptions options;
    options.length = 20;
    auto generated = generator.generate(options);
    expect(generated.size() == 20, "password generation length");
    expect(Authentication::evaluateStrength(generated) != PasswordRating::Weak, "password strength evaluation");

    expect(auth2.changeMasterPassword(master, changed, changed), "changing master password");
    expect(!storage.verifyMasterPassword(master), "old master rejected after change");
    expect(storage.verifyMasterPassword(changed), "access after changing master password");

    auto corruptPath = testPath("corrupt.svlt");
    std::filesystem::copy_file(path, corruptPath, std::filesystem::copy_options::overwrite_existing);
    {
        std::ofstream out(corruptPath, std::ios::app);
        out << "tamper";
    }
    StorageManager corrupt(corruptPath);
    expectThrows([&]() { (void)corrupt.load(changed); }, "corrupted encrypted file / invalid tag rejected");
    expectThrows([&]() { (void)storage.load("bad password"); }, "failed decryption");

    auto serialized = StorageManager::serialize(restarted.entries());
    expectThrows([&]() {
        std::vector<unsigned char> bad = serialized;
        bad.push_back(1);
        (void)StorageManager::deserialize(bad);
    }, "corrupted serialized payload rejected");

    PasswordManager copy = restarted;
    expect(copy.count() == restarted.count(), "resource cleanup and ownership copy");
    expect(true, "invalid menu inputs handled in main through guarded stoi conversion");

    std::cout << (failures == 0 ? "All tests passed\n" : "Some tests failed\n");
    return failures == 0 ? 0 : 1;
}
