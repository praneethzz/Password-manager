#ifndef SECUREVAULT_ENCRYPTIONSERVICE_H
#define SECUREVAULT_ENCRYPTIONSERVICE_H

#include <cstdint>
#include <string>
#include <vector>

struct EncryptedBlob {
    std::vector<unsigned char> salt;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    unsigned long iterations = 200000;
};

class EncryptionService {
public:
    static constexpr std::size_t KeySize = 32;
    static constexpr std::size_t SaltSize = 16;
    static constexpr std::size_t NonceSize = 12;
    static constexpr std::size_t TagSize = 16;

    std::vector<unsigned char> randomBytes(std::size_t length) const;
    std::vector<unsigned char> deriveKey(const std::string& masterPassword,
                                         const std::vector<unsigned char>& salt,
                                         unsigned long iterations) const;
    EncryptedBlob encrypt(const std::vector<unsigned char>& plaintext,
                          const std::string& masterPassword,
                          unsigned long iterations = 200000) const;
    std::vector<unsigned char> decrypt(const EncryptedBlob& blob,
                                       const std::string& masterPassword) const;
};

std::string base64Encode(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> base64Decode(const std::string& text);

#endif
