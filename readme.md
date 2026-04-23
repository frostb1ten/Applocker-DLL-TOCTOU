# AppLocker DLL Rule TOCTOU Bypass (appid.sys)

**Proof-of-Concept** for a time-of-check-to-time-of-use (TOCTOU) race condition in `appid.sys!SrpVerifyDll`.

This allows a **standard unprivileged user** to bypass AppLocker DLL enforcement rules on Windows 11.

> **Note:** This is a demonstration PoC only. It proves the race condition exists and shows how the bypass works in practice. It is **not** a full weaponized exploit or a universal bypass tool. If applocker is already enabled then this won't run you need to chain or find another way to run such as running in PowerShell without C :)

### Description
When `SrpVerifyDll` (IOCTL `0x225804` on `\Device\SrpDevice`) fails the initial `ObOpenObjectByPointer` check, it falls back to `ZwDuplicateObject`. Between the first handle reference and the duplicate, a racing thread can close the handle and force kernel pool reuse of the `FILE_OBJECT` address. This defeats the driver's pointer comparison, causing AppLocker policy to be evaluated against the **wrong file**.

Result: A DLL explicitly denied by AppLocker can return `ALLOWED`.

### PoC DLL Usage
- `C:\Windows\System32\kernel32.dll` -> Used for pool spraying in the racing thread. This is a **valid allowed** system DLL.
- `C:\Windows\System32\ntdll.dll` -> Copied to `poc.dll` in the temp folder. This is the DLL that is explicitly **denied** by your AppLocker rule.

The race tricks the driver into checking the allowed DLL (`kernel32.dll`) instead of your denied DLL (`poc.dll`).

Race: 31 allowed / 2495 denied / 2474 error (5000 iterations)
