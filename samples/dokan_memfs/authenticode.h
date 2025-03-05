#ifndef SIGNATURE_VERIFIER_H
#define SIGNATURE_VERIFIER_H

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <string>
#include <psapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

class SignatureVerifier {
public:
  explicit SignatureVerifier(const std::wstring &filePath);
  bool VerifySignature();
  std::wstring GetCertificateThumbprint();
  std::wstring GetProcessPath(DWORD processID);
  void SetProcessPath(const std::wstring &filePath);

private:
  std::wstring filePath;
  std::wstring ExtractThumbprint(PCCERT_CONTEXT certContext);
};

#endif // SIGNATURE_VERIFIER_H
