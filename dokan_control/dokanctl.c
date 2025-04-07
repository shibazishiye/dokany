/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2020 - 2025 Google, Inc.
  Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
  Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

  http://dokan-dev.github.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include "../dokan/dokan.h"
#include "../dokan/dokanc.h"
#include <ShlObj.h>

#define DOKAN_DRIVER_FULL_PATH                                                 \
  L"%SystemRoot%\\system32\\drivers\\dokan" DOKAN_MAJOR_API_VERSION L".sys"

int ShowUsage() {
  fprintf(stderr,
          "tdactl /u MountPoint\n"
          "tdactl /u M\n"
          "tdactl /a [d|n|a]\n"
          "tdactl /x [d|n|a]\n"
          "tdactl /v\n"
          "\n"
          "Example:\n"
          "  /u M                : Unmount M: drive\n"
          "  /u C:\\mount\\dokan   : Unmount mount point C:\\mount\\dokan\n"
          "  /a d                : Install driver\n"
          "  /a n                : Install network provider\n"
          "  /x d                : Remove driver\n"
          "  /x n                : Remove network provider\n"
          "  /l a                : List current mount points\n"
          "  /d [0-7]            : Enable Kernel Debug output\n"
          "  /v                  : Print Dokan version\n");
  return EXIT_FAILURE;
}

int DefaultCaseOption() {
  fprintf(stderr, "Unknown option - Use /? to show usage\n");
  return EXIT_FAILURE;
}

int Unmount(LPCWSTR MountPoint) {
  int status = EXIT_SUCCESS;

  if (!DokanRemoveMountPoint(MountPoint)) {
    status = EXIT_FAILURE;
  }

  fwprintf(stdout, L"Unmount status = %d\n", status);
  return status;
}

int InstallDriver(LPCWSTR driverFullPath) {
  fprintf(stdout, "Installing driver...\n");
  if (GetFileAttributes(driverFullPath) == INVALID_FILE_ATTRIBUTES) {
    fwprintf(stderr, L"Error the file '%ls' does not exist.\n", driverFullPath);
    return EXIT_FAILURE;
  }

  if (!DokanServiceInstall(DOKAN_DRIVER_SERVICE, SERVICE_FILE_SYSTEM_DRIVER,
                           DOKAN_DRIVER_FULL_PATH)) {
    fprintf(stderr, "Driver install failed\n");
    return EXIT_FAILURE;
  }

  fprintf(stdout, "Driver installation succeeded!\n");
  return EXIT_SUCCESS;
}

int DeleteDokanService(LPCWSTR ServiceName) {
  fwprintf(stdout, L"Removing '%ls'...\n", ServiceName);
  if (!DokanServiceDelete(ServiceName)) {
    fwprintf(stderr, L"Error removing '%ls'\n", ServiceName);
    return EXIT_FAILURE;
  }
  fwprintf(stdout, L"'%ls' removed.\n", ServiceName);
  return EXIT_SUCCESS;
}

#define GetOption(argc, argv, index)                                           \
  (((argc) > (index) && wcslen((argv)[(index)]) == 2 &&                        \
    (argv)[(index)][0] == L'/')                                                \
       ? towlower((argv)[(index)][1])                                          \
       : L'\0')

int __cdecl wmain(int argc, PWCHAR argv[]) {
  size_t i;
  WCHAR fileName[MAX_PATH];
  WCHAR driverFullPath[MAX_PATH] = {0};
  PVOID wow64OldValue;
  BOOL isAdmin;

  isAdmin = IsUserAnAdmin();

  DokanUseStdErr(TRUE); // Set dokan library debug output

  Wow64DisableWow64FsRedirection(&wow64OldValue); // Disable system32 direct
  // setlocale(LC_ALL, "");

  GetModuleFileName(NULL, fileName, MAX_PATH);

  // search the last "\"
  for (i = wcslen(fileName) - 1; i > 0 && fileName[i] != L'\\'; --i) {
    ;
  }
  fileName[i] = L'\0';

  ExpandEnvironmentStringsW(DOKAN_DRIVER_FULL_PATH, driverFullPath, MAX_PATH);

  fwprintf(stdout, L"Driver path: '%ls'\n", driverFullPath);

  WCHAR option = GetOption(argc, argv, 1);
  if (option == L'h') {
    return ShowUsage();
  }

  if (!isAdmin &&
      (option == L'a' || option == L'x' || option == L'd' || option == L'u')) {
    fprintf(stderr, "Admin rights required to process this operation\n");
    return EXIT_FAILURE;
  }

  switch (option) {
  // Admin rights required
  case L'a': {
    WCHAR type = towlower(argv[2][0]);
    int result = EXIT_SUCCESS;
    if (type != L'd' && type != L'n' && type != L'a') {
      return DefaultCaseOption();
    }
    if (type == L'd' || type == L'a') {
      result = InstallDriver(driverFullPath);
    }
    if (result != EXIT_SUCCESS || (type != L'n' && type != L'a')) {
      return result;
    }
    if (DokanNetworkProviderInstall()) {
      fprintf(stdout, "Network provider install ok\n");
    } else {
      fprintf(stderr, "Network provider install failed\n");
      result = EXIT_FAILURE;
    }
    return result;
  }

  case L'x': {
    WCHAR type = towlower(argv[2][0]);
    int result = EXIT_SUCCESS;
    if (type != L'd' && type != L'n' && type != L'a') {
      return DefaultCaseOption();
    }
    if (type == L'd' || type == L'a') {
      result = DeleteDokanService(DOKAN_DRIVER_SERVICE);
    }
    if (result != EXIT_SUCCESS || (type != L'n' && type != L'a')) {
      return result;
    }
    if (DokanNetworkProviderUninstall()) {
      fprintf(stdout, "Network provider remove ok\n");
    } else {
      fprintf(stderr, "Network provider remove failed\n");
      result = EXIT_FAILURE;
    }
    return result;
  }

  case L'd': {
    WCHAR type = towlower(argv[2][0]);
    if (L'0' > type || type > L'7')
      return DefaultCaseOption();

    ULONG mode = type - L'0';
    if (DokanSetDebugMode(mode)) {
      fprintf(stdout, "set debug mode ok\n");
    } else {
      fprintf(stderr, "set debug mode failed\n");
      return EXIT_FAILURE;
    }
  } break;

  case L'u': {
    if (argc < 3) {
      return DefaultCaseOption();
    }
    return Unmount(argv[2]);
  }

  // No admin rights required
  case L'l': {
    ULONG nbRead = 0;
    PDOKAN_MOUNT_POINT_INFO dokanMountPointInfo =
        DokanGetMountPointList(FALSE, &nbRead);
    if (dokanMountPointInfo == NULL) {
      fwprintf(stderr, L"  Cannot retrieve mount point list.\n");
      return EXIT_FAILURE;
    }

    fwprintf(stdout, L"  Mount points: %lu\n", nbRead);
    for (ULONG p = 0; p < nbRead; ++p)
      fwprintf(stdout, L"  %lu# MountPoint: %ls - UNC: %ls - DeviceName: %ls\n",
               p, dokanMountPointInfo[p].MountPoint,
               dokanMountPointInfo[p].UNCName,
               dokanMountPointInfo[p].DeviceName);
    DokanReleaseMountPointList(dokanMountPointInfo);
  } break;

  case L'v': {
    fprintf(stdout, "tdactl : %s %s\n", __DATE__, __TIME__);
    fprintf(stdout, "Dokan version : %ld\n", DokanVersion());
    fprintf(stdout, "Dokan driver version : 0x%lx\n", DokanDriverVersion());
  } break;

  default:
    return DefaultCaseOption();
  }

  return EXIT_SUCCESS;
}
