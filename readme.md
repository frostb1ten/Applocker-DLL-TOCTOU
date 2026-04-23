# AppLocker DLL Rule TOCTOU Bypass (appid.sys)

**Proof-of-Concept** for a time-of-check-to-time-of-use (TOCTOU) race condition in `appid.sys!SrpVerifyDll`.

This allows a **standard unprivileged user** to bypass AppLocker DLL enforcement rules on Windows 11.

> **Note:** This is a demonstration PoC only. It proves the race condition exists and shows how the bypass works in practice. It is **not** a full weaponized exploit or a universal bypass tool.

### Description
When `SrpVerifyDll` (IOCTL `0x225804` on `\Device\SrpDevice`) fails the initial `ObOpenObjectByPointer` check, it falls back to `ZwDuplicateObject`. Between the first handle reference and the duplicate, a racing thread can close the handle and force kernel pool reuse of the `FILE_OBJECT` address. This defeats the driver's pointer comparison, causing AppLocker policy to be evaluated against the **wrong file**.

Result: A DLL explicitly denied by AppLocker can return `ALLOWED`.
