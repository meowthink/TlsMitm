# WinDivert 2.2.2 (x64)

`x64/WinDivert.dll` and `x64/WinDivert64.sys` are unmodified files from the upstream
[WinDivert](https://github.com/basil00/WinDivert) 2.2.2 release, taken from the binaries embedded in
the `WindivertDotnet` 1.1.2 NuGet package. Both are embedded into `TlsMitm.dll` as resources and
unpacked to `%APPDATA%\TlsMitm\windivert-2.2.2\x64` on first run.

```
c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2  x64/WinDivert.dll
8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2  x64/WinDivert64.sys
```

x64 only: the DLL is loaded by the proxy process itself, never into an intercepted client. Clients
of any bitness are still captured, because the filtering happens in the kernel driver.
`WinDivert32.sys` would only be used on a 32-bit OS, which this project does not run on.

Licensed under the GNU Lesser General Public License v3 (or GPL v2 at your option); see `COPYING`
and `COPYING.LESSER`.
