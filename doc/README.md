# Ion Core Documentation

Table of Contents
-----------------
- [Ion Core Documentation](#Ion-Core-Documentation)
  - [Table of Contents](#Table-of-Contents)
  - [Setup](#Setup)
  - [Running](#Running)
    - [Unix](#Unix)
    - [Windows](#Windows)
    - [macOS](#macOS)
    - [Need Help?](#Need-Help)
  - [Building](#Building)
  - [Development](#Development)
  - [Resources](#Resources)
  - [Miscellaneous](#Miscellaneous)
  - [License](#License)

## Setup
[Ion Core](http://core.ioncoin.org/) is the original ION client and it builds the backbone of the network. However, it downloads and stores the entire history of ION transactions; depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more. Thankfully you only have to do this once.

## Running

The following are some helpful notes on how to run ION Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/ion-qt` (GUI) or
- `bin/iond` (headless)

### Windows

Unpack the files into a directory, and then run ion-qt.exe.

### macOS

Drag Ion-Qt to your applications folder, and then run Ion-Qt.

### Need Help?

- See the documentation at the [Ion Wiki](https://github.com/cevap/ion/wiki) and [Ionomy Wiki](https://github.com/ionomy/ion/wiki)
for help and more information.
- Ask for help on [Discord chat](https://discord.gg/vuZn7gC)

## Building
The following are developer notes on how to build ION Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [Gitian Building Guide](gitian-building.md)

## Development
The ION Core repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Multiwallet Qt Development](multiwallet-qt.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation](https://cevap.github.io/ion-docs/)
- [Translation Process](translation_process.md)
- [Unit Tests](unit-tests.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Dnsseed Policy](dnsseed-policy.md)

## Resources

- Discuss on the [ION community](https://ion.community/) forum.
- Join [Ion Discord](https://discord.gg/vuZn7gC).

## Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)

## License
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
