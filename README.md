# npcap_sys
Bindings to Npcap Windows API

## NOTICE!
- This library is under heavy and rapid development. It is not recommended to fork or clone this library at this time as the repo will be rebased before v0.1.0 is stabilized

## License Notice
- Npcap is not an open source software project, please review notices and licenses provided in below links
  - [Npcap License Snapshot](../../blob/master/NPCAP_LICENSE)
  - [Npcap License](https://raw.githubusercontent.com/nmap/npcap/master/LICENSE)
  - [Npcap Repository](https://github.com/nmap/npcap)
  - [Npcap Homepage](https://nmap.org/npcap/)

## Library Usage
- This library will export a few features by default for convenience as the expectation is these are desired features when using the npcap api. This may be ovverriden by providing `--no-default-features` and optionally suplementing with a list of desired features using `--features "feature-name"`

## Building
- You must use a version of Rust which uses the MSVC toolchain
- You must have [Npcap](https://nmap.org/npcap/) installed (tested with version Npcap 0.99-r9 and Npcap SDK 1.01)
- You must place `Packet.lib` from the [Npcap SDK](https://nmap.org/npcap/)
   in a directory named `lib`, in the root of this repository. Alternatively, you can use any of the
   locations listed in the `%LIB%`/`$Env:LIB` environment variables. For the 64 bit toolchain it is
   in `npcap-sdk/Lib/x64/Packet.lib`, for the 32 bit toolchain, it is in `npcap-sdk/Lib/Packet.lib`.
  - For x64 build in powershell, you can run this in your powershell session first `$env:lib = "C:\WinDev\npcap-sdk-1.01\Lib\x64\"` assuming you have extracted the 1.01 version of the sdk into `C:\WinDev\`
  - As an easier alternative, you can also go to Control Panel / System / Advanced / Env Vars and add a User variable called `lib` with the contents `C:\WinDev\npcap-sdk-1.01\Lib\x64\;`. Note the semi-colon, to make it easier to add more lib locations later.
- To run tests, run `cargo test --features "everything"` from crate root

## Attributions
- This library is heavily influenced with a lot of copy/paste from the following projects. Many authors have contributed to these projects, but special attribution should go to Robert Clipsham and Peter Atashian as lead authors of below projects.
  - [libpnet](https://github.com/libpnet/libpnet)
  - [winapi-rs](https://github.com/retep998/winapi-rs)
