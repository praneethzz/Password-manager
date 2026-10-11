#include "EncryptionService.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <stdexcept>

#ifndef BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
#define BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG 0x00000001
#endif

namespace {
class AlgHandle {
private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
public:
    explicit AlgHandle(BCRYPT_ALG_HANDLE handle = nullptr) : handle_(handle) {}
    ~AlgHandle() { if (handle_) BCryptCloseAlgorithmProvider(handle_, 0); }
    BCRYPT_ALG_HANDLE get() const { return handle_; }
    BCRYPT_ALG_HANDLE* put() { return &handle_; }
};

class KeyHandle {
private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
public:
    explicit KeyHandle(BCRYPT_KEY_HANDLE handle = nullptr) : handle_(handle) {}
    ~KeyHandle() { if (handle_) BCryptDestroyKey(handle_); }
    BCRYPT_KEY_HANDLE get() const { return handle_; }
    BCRYPT_KEY_HANDLE* put() { return &handle_; }
};

void check(NTSTATUS status, const char* message) {
    if (status < 0) throw std::runtime_error(message);
}

const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

std::vector<unsigned char> EncryptionService::randomBytes(std::size_t length) const {
    std::vector<unsigned char> bytes(length);
    check(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG), "Secure random generation failed");
    return bytes;
}

std::vector<unsigned char> EncryptionService::deriveKey(const std::string& masterPassword,
                                                        const std::vector<unsigned char>& salt,
                                                        unsigned long iterations) const {
    AlgHandle alg;
    check(BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_SHA256_ALGORITHM, nullptr,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG), "PBKDF2 provider failed");
    std::vector<unsigned char> key(KeySize);
    check(BCryptDeriveKeyPBKDF2(alg.get(),
                                reinterpret_cast<PUCHAR>(const_cast<char*>(masterPassword.data())),
                                static_cast<ULONG>(masterPassword.size()),
                                const_cast<PUCHAR>(salt.data()),
                                static_cast<ULONG>(salt.size()),
                                iterations,
                                key.data(),
                                static_cast<ULONG>(key.size()),
                                0), "PBKDF2 key derivation failed");
    return key;
}

EncryptedBlob EncryptionService::encrypt(const std::vector<unsigned char>& plaintext,
                                         const std::string& masterPassword,
                                         unsigned long iterations) const {
    EncryptedBlob blob;
    blob.iterations = iterations;
    blob.salt = randomBytes(SaltSize);
    blob.nonce = randomBytes(NonceSize);
    auto key = deriveKey(masterPassword, blob.salt, iterations);

    AlgHandle alg;
    check(BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_AES_ALGORITHM, nullptr, 0), "AES provider failed");
    check(BCryptSetProperty(alg.get(), BCRYPT_CHAINING_MODE,
                            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                            static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)), 0),
          "AES-GCM mode setup failed");

    KeyHandle aesKey;
    check(BCryptGenerateSymmetricKey(alg.get(), aesKey.put(), nullptr, 0, key.data(),
                                     static_cast<ULONG>(key.size()), 0), "AES key setup failed");

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = blob.nonce.data();
    authInfo.cbNonce = static_cast<ULONG>(blob.nonce.size());
    blob.tag.resize(TagSize);
    authInfo.pbTag = blob.tag.data();
    authInfo.cbTag = static_cast<ULONG>(blob.tag.size());

    ULONG cipherSize = 0;
    check(BCryptEncrypt(aesKey.get(),
                        const_cast<PUCHAR>(plaintext.data()),
                        static_cast<ULONG>(plaintext.size()),
                        &authInfo, nullptr, 0, nullptr, 0, &cipherSize, 0),
          "AES-GCM encryption sizing failed");
    blob.ciphertext.resize(cipherSize);
    check(BCryptEncrypt(aesKey.get(),
                        const_cast<PUCHAR>(plaintext.data()),
                        static_cast<ULONG>(plaintext.size()),
                        &authInfo, nullptr, 0, blob.ciphertext.data(), cipherSize, &cipherSize, 0),
          "AES-GCM encryption failed");
    blob.ciphertext.resize(cipherSize);
    std::fill(key.begin(), key.end(), 0);
    return blob;
}

std::vector<unsigned char> EncryptionService::decrypt(const EncryptedBlob& blob,
                                                      const std::string& masterPassword) const {
    auto key = deriveKey(masterPassword, blob.salt, blob.iterations);

    AlgHandle alg;
    check(BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_AES_ALGORITHM, nullptr, 0), "AES provider failed");
    check(BCryptSetProperty(alg.get(), BCRYPT_CHAINING_MODE,
                            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                            static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)), 0),
          "AES-GCM mode setup failed");

    KeyHandle aesKey;
    check(BCryptGenerateSymmetricKey(alg.get(), aesKey.put(), nullptr, 0, key.data(),
                                     static_cast<ULONG>(key.size()), 0), "AES key setup failed");

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(blob.nonce.data());
    authInfo.cbNonce = static_cast<ULONG>(blob.nonce.size());
    authInfo.pbTag = const_cast<PUCHAR>(blob.tag.data());
    authInfo.cbTag = static_cast<ULONG>(blob.tag.size());

    ULONG plainSize = 0;
    NTSTATUS first = BCryptDecrypt(aesKey.get(),
                                   const_cast<PUCHAR>(blob.ciphertext.data()),
                                   static_cast<ULONG>(blob.ciphertext.size()),
                                   &authInfo, nullptr, 0, nullptr, 0, &plainSize, 0);
    check(first, "AES-GCM decryption sizing failed");
    std::vector<unsigned char> plaintext(plainSize);
    NTSTATUS second = BCryptDecrypt(aesKey.get(),
                                    const_cast<PUCHAR>(blob.ciphertext.data()),
                                    static_cast<ULONG>(blob.ciphertext.size()),
                                    &authInfo, nullptr, 0, plaintext.data(), plainSize, &plainSize, 0);
    std::fill(key.begin(), key.end(), 0);
    if (second < 0) throw std::runtime_error("Invalid password or tampered vault data");
    plaintext.resize(plainSize);
    return plaintext;
}

std::string base64Encode(const std::vector<unsigned char>& bytes) {
    std::string out;
    int val = 0;
    int bits = -6;
    for (unsigned char c : bytes) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(B64[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(B64[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::vector<unsigned char> base64Decode(const std::string& text) {
    std::vector<int> table(256, -1);
    for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(B64[i])] = i;
    std::vector<unsigned char> out;
    int val = 0;
    int bits = -8;
    for (unsigned char c : text) {
        if (c == '=') break;
        if (table[c] == -1) throw std::runtime_error("Invalid base64 data");
        val = (val << 6) + table[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<unsigned char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}
