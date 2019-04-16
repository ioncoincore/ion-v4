(note: this is a temporary file, to be added-to by anybody, and moved to release-notes at release time)

Ion Core version 3.2.00 is now available from:  <https://github.com/cevap/ion/releases>

This is a new major version release, including various bug fixes and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at github: <https://github.com/cevap/ion/issues>

#### Downloads and statistics
![GitHub Releases (by Release)](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/total.svg?style=social)
- ###### windows
  - [![Download ion installer for Windows 32-bit](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-win32-setup-unsigned.exe.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-win32-setup-unsigned.exe) [![Download ion installer for Windows 64-bit](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-win64-setup-unsigned.exe.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-win64-setup-unsigned.exe)
  - [![Download ion binaries for Windows 32-bit](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-win32.zip.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-win32.zip) [![Download ion binaries for Windows 64-bit](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-win64.zip.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-win64.zip)
- ###### linux Downloads
  - _i686/x86_64_
    - [![Download ion v3.2.00 for Linux 32-bit (i686)](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-i686-pc-linux-gnu.tar.xz.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-i686-pc-linux-gnu.tar.xz) [![Download ion v3.2.00 for Linux 64-bit (x86_x64)](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-x86_64-linux-gnu.tar.xz.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-x86_64-linux-gnu.tar.xz)
  - _arm/aarch64/riscv64_
    - [![Download ion v3.2.00 for ARM Linux](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-arm-linux-gnueabihf.tar.xz.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-arm-linux-gnueabihf.tar.xz) [![Download ion v3.2.00 for aarch64 Linux](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-aarch64-linux-gnu.tar.xz.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-aarch64-linux-gnu.tar.xz) [![Download ion v3.2.00 for riscv64 Linux](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-riscv64-linux-gnu.tar.xz.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-riscv64-linux-gnu.tar.xz)
- ###### mac os
  - [![Download ion Setup for OSX 32-bit](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-osx-unsigned.dmg.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-osx-unsigned.dmg) [![Download ion Setup for OSX 64-bit](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/ion-3.2.00-osx64.tar.xz.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/ion-3.2.00-osx64.tar.xz)
- ###### checksums
  - [![Download SHA256SUMS.asc](https://img.shields.io/github/downloads/ioncoincore/ion/v3.2.00/SHA256SUMS.asc.svg)](https://github.com/ioncoincore/ion/releases/download/v3.2.00/SHA256SUMS.asc)

Mandatory Update
==============


How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely shut down (which might take a few minutes for older versions), then run the installer (on Windows) or just copy over /Applications/Ion-Qt (on Mac) or iond/ion-qt (on Linux).


Compatibility
==============

Ion Core is extensively tested on multiple operating systems using the Linux kernel, macOS 10.10+, and Windows 7 and later.

Microsoft ended support for Windows XP on [April 8th, 2014](https://www.microsoft.com/en-us/WindowsForBusiness/end-of-xp-support), No attempt is made to prevent installing or running the software on Windows XP, you can still do so at your own risk but be aware that there are known instabilities and issues. Please do not report issues about Windows XP to the issue tracker.

Ion Core should also work on most other Unix-like systems but is not frequently tested on them.
 
Notable Changes
==============


3.2.00 Change log
==============

Detailed release notes follow. This overview includes changes that affect behavior, not code moves, refactors and string updates. For convenience in locating the code changes and accompanying discussion, both the pull request and git merge commit are mentioned.

### Core Features

### Build System

Major update for automatic building. We have a system which builds on each change of master, providing binaries for all changes on our github master branch.

Each time when master branch changes, snapcraft starts building and publishes releases linux builds for _**amd64, i386, arm, aarch64, ppc64el and s390x**_ architectures. (_s390x has no qt binary_). Snapcraft auto releases to the _**edge**_ channel.

Beta channel is quite the same as edge channel, it is built automaticly on each change with a difference to edge channel is that launchpad builds every 6 hours (4 times a day) which is considered to be more stable than edge channel as building happens not on each commit on master. Launchpad checks in interval of 6 hours if there are any changes and if our github repository updated, then launchpad will create snap builds _**amd64, i386, arm, aarch64, ppc64el and s390x**_ and debian packages for _**amd64, i386 (Bionic, Cosmic)**_ from same commit.

#### snap

- Overview of **release/stable** channels: _**Release**_ and _**RC (Release Candidate)**_
  _released together with gitian from same commit hash providing with that all releases including windows and mac to be always from same commit ID/source_
  build on | channels | amd64 | i386 | arm | aarch64 | ppc64el | s390x | automatic<br>building | build<br>from branch | autobuild<br>interval
  :------: | :-----: | :---: | :--: | :-: | :-----: | :-----: | :---: | :-------------------: | :------------------: | --------------------:
  launchpad<br>(_Release/RC_) |  _**stable**_<br>_**candidate**_ | yes | yes | yes | yes | yes | yes | yes | master | only manual release
  snapcraft<br>(_Release/RC)_ | _**stable**_<br>_**candidate**_ | yes | yes | yes | yes | yes | yes | yes | master | only manual release

- Overview of **development channels**:
  build on | channel | amd64 | i386 | arm | aarch64 | ppc64el | s390x | automatic<br>building | build<br>from branch | autobuild<br>interval |
  :-----  | :-----: | :---: | :--: | :-: | :-----: | :-----: | :---: | :-------------------: | :----: | -----------------:
  launchpad<br>(_unstable_) | _**beta**_ | yes | yes | yes | yes | yes | yes | yes | master | every 6 hours
  snapcraft<br>(_very unstable_) | _**edge**_ | yes | yes | yes | yes | yes | yes | yes | master | on each commit

- Installation notes
  Default install (_installs from stable channel_): `sudo snap install ioncore`
  _If you already installed ioncore snap and want to change channel, type_ `sudo snap refresh --YOURCHANNEL ioncore`, see examples bellow 
  release (stable channel)| release candidate<br>(candidate channel) | unstable (beta) | very unstable (edge)
  :-----: | :---------------: | :--: | :--:
  | `sudo snap install --stable ioncore` | `sudo snap install --candidate ioncore` | `sudo snap install --beta ioncore` | `sudo snap install --edge ioncore`

  if ioncore/another channel is installed then run `sudo snap refresh --candidate ioncore`

Please check general information about ioncore snap [doc/snap/README.md](doc/snap/README.md) for more detailed information about installation.

#### Debian packages

new debian packages: 
  
  iond ion-cli ion-tx ion-qt ion-full ion-dev

- iond package includes ion-cli_
- ion-full includes iond, ion-cli, ion-tx and ion-qt 
- ion-dev includes iond, ion-cli, ion-tx, ion-qt, test_ion and test_ion-qt
 
We provide debian packages of debian (_same release process as with snap on launchpad, see tables above_)
- automatic build system on snapcraft and launchpad
  - [new repository for development channel](https://code.launchpad.net/~ionomy/ioncore/+git/trunk)

        https://code.launchpad.net/~ionomy/ioncore/+git/trunk

  - [new PPA for development channel]([ppa:ionomy/ion](https://launchpad.net/~ionomy/+archive/ubuntu/ion))

    You can update your system with unsupported packages from this untrusted PPA by adding ppa:ionomy/ion to your system's Software Sources

        sudo add-apt-repository ppa:ionomy/ion
        sudo apt-get update

  - refactored snapcraft and updated it to core18 (bionic)
    - patches and desktop files moved to snap/contrib
    - move snap/README.md to doc/README.md
 
### P2P Protocol and Network Code

### GUI
- New splash screens
- New daemon icons+sources for testnet and regtest
- New QT GUI icons+sources for testnet and regtest
- Improve usability by using snapcraft icons and splash screen with visible snapcraft text
  _if somebody has installed packages from our repo and snap devel channel, then users were not properly able to distinguish beetwen shortcuts launching snaps or normal binaries_

### RPC/REST
 - Protocol upgrade to 95704 (79ad40cba363db5e0bba03fa591fecd7763eda0e)

### Wallet
 
### Miscellaneous
 
 
## Credits

Thanks to everyone who directly contributed to this release:


As well as everyone that helped translating on [Transifex](https://www.transifex.com/cevap/iocoin//), the QA team during Testing and the Node hosts supporting our Testnet.
