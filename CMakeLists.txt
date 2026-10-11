cmake_minimum_required(VERSION 3.16)
project(SecureVault LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

set(SECUREVAULT_SOURCES
    src/Authentication.cpp
    src/EncryptionService.cpp
    src/PasswordEntry.cpp
    src/PasswordGenerator.cpp
    src/PasswordManager.cpp
    src/StorageManager.cpp
)

add_executable(SecureVault src/main.cpp ${SECUREVAULT_SOURCES})
add_executable(SecureVaultTests tests/test_main.cpp ${SECUREVAULT_SOURCES})
add_executable(ConceptDemo examples/concept_demo.cpp)

if (WIN32)
    target_link_libraries(SecureVault bcrypt)
    target_link_libraries(SecureVaultTests bcrypt)
endif()

enable_testing()
add_test(NAME SecureVaultTests COMMAND SecureVaultTests)
