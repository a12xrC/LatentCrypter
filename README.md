# LatentCrypter
FUD Runtime Crypter w Interactive CLI 
██████╗  █████╗ ████████╗███████╗███╗   ██╗████████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝████╗  ██║╚══██╔══╝
██████╔╝███████║   ██║   █████╗  ██╔██╗ ██║   ██║   
██╔═══╝ ██╔══██║   ██║   ██╔══╝  ██║╚██╗██║   ██║   
██║     ██║  ██║   ██║   ███████╗██║ ╚████║   ██║   
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝   ╚═╝   

Manual-mapping, ChaCha20-encrypted DLL crypter + injector. Fully runtime, shellcode-based, and paranoid-friendly.
Features
- ChaCha20 Encryption: Secure, fast, and stream-based cipher

- Manual Mapping: Bypasses LoadLibrary, resolves EAT and relocations manually

- Obfuscation Layer: Optional junk execution noise to confuse heuristics

- Shellcode Stub Injection: Minimal on-disk footprint

- CLI-Friendly: Full command-line interface with flags

- Interactive PID Picker: Choose target process with a live list

-Log Support: Optional logging to file

- Cross-Compatible: 32-bit & 64-bit targets (depending on build)
