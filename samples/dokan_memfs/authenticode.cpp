#include "authenticode.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>


SignatureVerifier::SignatureVerifier(const std::wstring &filePath) : filePath(filePath) {}

void SignatureVerifier::SetProcessPath(const std::wstring &filePath2) {
  filePath = filePath2;
}

bool SignatureVerifier::VerifySignature() {
  WINTRUST_FILE_INFO fileInfo = {0};
  fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
  fileInfo.pcwszFilePath = filePath.c_str();

  WINTRUST_DATA trustData = {0};
  trustData.cbStruct = sizeof(WINTRUST_DATA);
  trustData.dwUIChoice = WTD_UI_NONE;
  trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  trustData.dwUnionChoice = WTD_CHOICE_FILE;
  trustData.pFile = &fileInfo;
  trustData.dwStateAction = WTD_STATEACTION_VERIFY;
  trustData.dwProvFlags = WTD_SAFER_FLAG;

  GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

  trustData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(NULL, &policyGUID, &trustData);

  if (status == ERROR_SUCCESS) {
    std::wcout << L"The file is digitally signed and valid.\n";
    return true;
  } else if (status == TRUST_E_NOSIGNATURE) {
    std::wcout << L"The file is not digitally signed.\n";
  } else {
    std::wcout << L"Signature verification failed. Error: " << std::hex
               << status << std::endl;
  }
  return false;
}

std::wstring SignatureVerifier::ExtractThumbprint(PCCERT_CONTEXT certContext) {
  std::wcout << L"PrintCertificateDetails: " << std::endl;

  if (!certContext)
    return L"";

  DWORD nameSize = CertGetNameStringW(
      certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
  std::wstring subjectName(nameSize, L'\0');
  CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                     &subjectName[0], nameSize);

  std::wcout << L"Signer: " << subjectName.c_str() << std::endl;

  BYTE sha1Thumbprint[20]; // SHA-1 hash is 20 bytes long
  DWORD thumbprintSize = sizeof(sha1Thumbprint);

  if (CertGetCertificateContextProperty(certContext, CERT_HASH_PROP_ID,
                                        sha1Thumbprint, &thumbprintSize)) {
    std::wstringstream hexStream;
    hexStream << std::uppercase << std::setfill(L'0');

    for (DWORD i = 0; i < thumbprintSize; i++) {
      hexStream << std::setw(2) << std::hex << (int)sha1Thumbprint[i] << L"";
    }

    std::wstring thumbprintStr = hexStream.str();
    std::wcout << L"SHA-1 Thumbprint: " << thumbprintStr << std::endl;

    return thumbprintStr; // Return the generated SHA-1 string
  }

  return L"Failed to retrieve thumbprint.";
}

std::wstring SignatureVerifier::GetCertificateThumbprint() {
  HCERTSTORE certStore = NULL;
  HCRYPTMSG cryptMsg = NULL;
  std::wstring sign;

  std::wcout << L"ExtractSignatureDetails: " << std::endl;

  if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
                        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                        CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL,
                        &certStore, &cryptMsg, NULL)) {
    std::wcout << L"Failed to extract signature from file.\n";
    return NULL;
  }

  DWORD signerInfoSize = 0;
  if (!CryptMsgGetParam(cryptMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL,
                        &signerInfoSize)) {
    std::wcout << L"Failed to get signer info size.\n";
    return NULL;
  }

  std::vector<BYTE> signerInfoBuffer(signerInfoSize);
  if (!CryptMsgGetParam(cryptMsg, CMSG_SIGNER_INFO_PARAM, 0,
                        signerInfoBuffer.data(), &signerInfoSize)) {
    std::wcout << L"Failed to retrieve signer info.\n";
    return NULL;
  }

  CMSG_SIGNER_INFO *signerInfo =
      reinterpret_cast<CMSG_SIGNER_INFO *>(signerInfoBuffer.data());

  CERT_INFO certInfo = {0};
  certInfo.Issuer = signerInfo->Issuer;
  certInfo.SerialNumber = signerInfo->SerialNumber;

  PCCERT_CONTEXT certContext = CertFindCertificateInStore(
      certStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
      CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
  if (certContext) {
    sign = ExtractThumbprint(certContext);
    CertFreeCertificateContext(certContext);
  } else {
    std::wcout << L"Failed to retrieve certificate context.\n";
  }

  CertCloseStore(certStore, 0);
  CryptMsgClose(cryptMsg);

  return sign;
}

std::wstring SignatureVerifier::GetProcessPath(DWORD processID) {
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
  if (!hProcess) {
    std::wcerr << L"❌ Failed to open process " << processID << L", Error: "
               << GetLastError() << std::endl;
    return L"";
  }

  WCHAR pathBuffer[MAX_PATH];
  DWORD pathSize = MAX_PATH;

  if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, &pathSize)) {
    CloseHandle(hProcess);
    return std::wstring(pathBuffer);
  } else {
    std::wcerr << L"⚠ Failed to get process path. Error: " << GetLastError()
               << std::endl;
  }

  CloseHandle(hProcess);
  return L"";
}

void SignatureVerifier::SetWhiteList(
    std::vector<std::wstring> newSignaturewhiteList) {
  signaturewhiteList.clear();
  signaturewhiteList.assign(newSignaturewhiteList.begin(),
                            newSignaturewhiteList.end());
}

bool SignatureVerifier::IsValidProcess(DWORD processID) {
  std::wstring filePath;
  std::wstring sign;

  filePath = GetProcessPath(processID);

  std::wcout << L"path: " << filePath << std::endl;

  SetProcessPath(filePath);

  if (VerifySignature()) {
    sign = GetCertificateThumbprint();
    std::wcout << L"sign: " << sign << std::endl;

    bool exists =
        (std::find(signaturewhiteList.begin(), signaturewhiteList.end(),
                   sign) != signaturewhiteList.end());

    return exists;
  }
  return false;
}

bool SignatureVerifier::IsValidSign(std::wstring sign) {
  if (signaturewhiteList.empty()) {
    return false;
  }
  if (sign.empty()) {
    return false;
  }

  bool exists = (std::find(signaturewhiteList.begin(), signaturewhiteList.end(),
                           sign) != signaturewhiteList.end());

  return exists;
}

//int main() {
//  DWORD pid;
//  std::wcout << L"Enter Process ID: ";
//  std::wcin >> pid;
//
//  SignatureVerifier verifier(L"");
//
//  bool isValid = verifier.IsValidProcess(pid);
//
//  std::wcout << L"It is qeual. " << isValid  << std::endl;
//
//
//  return 0;
//}
