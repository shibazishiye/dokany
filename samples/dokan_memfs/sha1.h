#pragma once

#ifndef SHA1HASH_H
#define SHA1HASH_H

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>

#pragma comment(lib, "bcrypt.lib")

class SHA1Hasher {
public:
    static bool ComputeSHA1(const std::wstring& filePath, std::vector<BYTE>& hashOutput);
    static std::wstring ByteArrayToHexString(const std::vector<BYTE>& bytes);
};

#endif // SHA1HASH_H
