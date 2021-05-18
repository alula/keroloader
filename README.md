# keroloader2

An application that implements a subset of Win32 API inside an x86 emulator needed by games based on Pixel's Kero engine (\[GK]ero Blaster, Pink Hour/Heaven, Haru to Shura).

WIP.

### Legality

KeroLoader is perfectly legal to use if you own a copy of the game on Steam (the Playism version might possibly work as well but I'm unable to test it rn since the store is dead).

- KeroLoader SteamAPI calls return the same values as in case where Steam is unavailable - Kero Blaster simply disables interactions with Steam's API if so. No DRM circumvention or other stuff is involved.
- KeroLoader uses a completely clean-room Win32 implementation, not based on anything but public domain MinGW headers and Microsoft's API documentation.

### Needed files
- `KeroBlaster.exe` and data (`rsc_k` folder) acquired from Steam (the Playism release might possibly work as well but it was never tested).
- 32-bit `msvcrt.dll` or `msvcr100.dll` (aka Windows builtin CRT or Visual Studio 2010 C runtime).