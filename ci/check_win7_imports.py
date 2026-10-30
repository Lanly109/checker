"""Reject known Win7-incompatible imports and external runtime dependencies.

Requires pefile==2024.8.26. This is a static guard, not a Win7 runtime test.
"""

import argparse
import sys

import pefile


# All imported DLLs must be standard Windows 7 desktop components. In
# particular, SDL, FreeType and the C/C++ runtime must be linked statically.
SYSTEM_DLLS = {
    "advapi32.dll", "bcrypt.dll", "comctl32.dll", "comdlg32.dll",
    "crypt32.dll", "d3d9.dll", "d3d11.dll", "dinput8.dll", "dsound.dll",
    "dwmapi.dll", "dxgi.dll", "gdi32.dll", "hid.dll", "imm32.dll",
    "iphlpapi.dll", "kernel32.dll", "msimg32.dll", "ntdll.dll",
    "ole32.dll", "oleaut32.dll", "opengl32.dll", "powrprof.dll",
    "psapi.dll", "rpcrt4.dll", "secur32.dll", "setupapi.dll",
    "shell32.dll", "shlwapi.dll", "user32.dll", "userenv.dll",
    "usp10.dll", "uxtheme.dll", "version.dll", "winhttp.dll",
    "wininet.dll", "winmm.dll", "winspool.drv", "wintrust.dll",
    "ws2_32.dll", "wtsapi32.dll",
}

UNSUPPORTED_FUNCTIONS = {
    "WaitOnAddress", "WakeByAddressAll", "WakeByAddressSingle", "ProcessPrng",
    "GetSystemTimePreciseAsFileTime", "GetTempPath2A", "GetTempPath2W",
    "SetThreadDescription", "GetDpiForWindow", "GetDpiForSystem",
    "GetSystemMetricsForDpi", "AdjustWindowRectExForDpi",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe")
    args = parser.parse_args()
    errors = []
    try:
        pe = pefile.PE(args.exe)
    except (OSError, pefile.PEFormatError) as exc:
        parser.error(str(exc))

    with pe:
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
            errors.append("Expected an x86 PE32 executable")
        version = (pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                   pe.OPTIONAL_HEADER.MinorSubsystemVersion)
        if version > (6, 1):
            errors.append(f"Subsystem version {version} is newer than Windows 7")

        imports = (getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                   + getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
        for entry in imports:
            dll = entry.dll.decode("ascii")
            if dll.lower() not in SYSTEM_DLLS:
                errors.append(f"Unexpected DLL dependency: {dll}")
            for symbol in entry.imports:
                if symbol.name:
                    name = symbol.name.decode("ascii")
                    if name in UNSUPPORTED_FUNCTIONS:
                        errors.append(f"Unsupported Win7 import: {dll}!{name}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Win7 import guard passed: {args.exe}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
