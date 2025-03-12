#include "sha1.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

bool SHA1Hasher::ComputeSHA1(const std::wstring& filePath, std::vector<BYTE>& hashOutput) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    BYTE hashValue[20]; // SHA-1 produces a 20-byte hash
    bool success = false;

    std::vector<char> buffer(4096);

    // Open file for reading
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::wcerr << L"Error opening file: " << filePath << std::endl;
        return false;
    }

    // Open the SHA-1 algorithm provider
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        std::wcerr << L"BCryptOpenAlgorithmProvider failed." << std::endl;
        goto Cleanup;
    }

    // Get the size of the hash object
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0) != STATUS_SUCCESS) {
        std::wcerr << L"BCryptGetProperty failed." << std::endl;
        goto Cleanup;
    }

    // Allocate the hash object
    pbHashObject = new BYTE[cbHashObject];
    if (!pbHashObject) {
        std::wcerr << L"Memory allocation failed." << std::endl;
        goto Cleanup;
    }

    // Create the hash handle
    if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != STATUS_SUCCESS) {
        std::wcerr << L"BCryptCreateHash failed." << std::endl;
        goto Cleanup;
    }

    // Read file in chunks and update the hash
    
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        if (BCryptHashData(hHash, (PUCHAR)buffer.data(), (ULONG)file.gcount(), 0) != STATUS_SUCCESS) {
            std::wcerr << L"BCryptHashData failed." << std::endl;
            goto Cleanup;
        }
    }

    // Get hash length
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbData, 0) != STATUS_SUCCESS || cbHash != sizeof(hashValue)) {
        std::wcerr << L"BCryptGetProperty for hash length failed." << std::endl;
        goto Cleanup;
    }

    // Get the final hash result
    if (BCryptFinishHash(hHash, hashValue, cbHash, 0) != STATUS_SUCCESS) {
        std::wcerr << L"BCryptFinishHash failed." << std::endl;
        goto Cleanup;
    }

    // Store hash
    hashOutput.assign(hashValue, hashValue + cbHash);
    success = true;

Cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) delete[] pbHashObject;
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

// Convert hash bytes to a readable hex string
std::wstring SHA1Hasher::ByteArrayToHexString(const std::vector<BYTE>& bytes) {
    std::wstringstream ss;
    ss << std::hex << std::uppercase; // Uppercase like 7-Zip and Get-FileHash
    for (BYTE b : bytes) {
        ss << std::setw(2) << std::setfill(L'0') << (int)b;
    }
    return ss.str();
}
