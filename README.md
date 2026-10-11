# SecureVault

SecureVault is a local console password manager written in C++17 for Windows.

## Technical Configuration

- Compiler used for verification: MSYS2 MinGW `g++` 15.2.0
- Crypto backend: Windows CNG through `bcrypt.dll`
- Encryption: AES-256-GCM with a fresh 96-bit nonce per save
- Key derivation: PBKDF2-HMAC-SHA256 with 200,000 iterations and a 128-bit salt
- Storage: encrypted `data/vault.svlt` with authenticated tamper detection

The program does not protect against a compromised host, malware, screen capture, keyloggers, or attacks against the running process memory. C++ strings are cleared in a few wrapper/destructor paths where practical, but operating systems and compiler optimizations can still leave historical copies in memory.

## Build

With CMake installed:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
ctest --test-dir build --output-on-failure
.\build\SecureVault.exe
```

Without CMake, using the MSYS2 MinGW compiler:

```powershell
C:\msys64\mingw64\bin\g++.exe -std=c++17 -Wall -Wextra -Iinclude src\main.cpp src\Authentication.cpp src\EncryptionService.cpp src\PasswordEntry.cpp src\PasswordGenerator.cpp src\PasswordManager.cpp src\StorageManager.cpp -lbcrypt -o SecureVault.exe
C:\msys64\mingw64\bin\g++.exe -std=c++17 -Wall -Wextra -Iinclude tests\test_main.cpp src\Authentication.cpp src\EncryptionService.cpp src\PasswordEntry.cpp src\PasswordGenerator.cpp src\PasswordManager.cpp src\StorageManager.cpp -lbcrypt -o SecureVaultTests.exe
.\SecureVaultTests.exe
.\SecureVault.exe
```

## Directory Tree

```text
SecureVault/
|-- include/
|-- src/
|-- tests/
|-- examples/
|-- data/
|-- CMakeLists.txt
|-- README.md
```
