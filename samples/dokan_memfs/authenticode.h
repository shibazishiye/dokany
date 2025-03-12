#ifndef SIGNATURE_VERIFIER_H
#define SIGNATURE_VERIFIER_H

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <string>
#include <psapi.h>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

class SignatureVerifier {
public:
  explicit SignatureVerifier(const std::wstring &filePath);
  bool VerifySignature();
  std::wstring GetCertificateThumbprint();
  std::wstring GetProcessPath(DWORD processID);
  void SetWhiteList(std::vector<std::wstring> newSignaturewhiteList);
  bool IsValidProcess(DWORD processID);
  bool IsValidSign(std::wstring sign);
  void SetProcessPath(const std::wstring &filePath);
  std::vector<std::wstring> signaturewhiteList = {
      L"8F985BE8FD256085C90A95D3C74580511A1DB975",  //Notepad.exe
      L"A731D48CD8E2A99BB91F7C096F40CEDF3A468BA6"}; //Notepad++

private:
  std::wstring filePath;
  std::wstring ExtractThumbprint(PCCERT_CONTEXT certContext);
};

#endif // SIGNATURE_VERIFIER_H
