## Ioncore Snap Builds
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/ioncore) 

[![Snap Status](https://build.snapcraft.io/badge/ioncoincore/ion.svg)](https://build.snapcraft.io/user/ioncoincore/ion)

- [IONCOINCORE SNAP FAQ](#ioncoincore-snap-faq)
  - [How to install snapd?](#how-to-install-snapd)
  - [How to install ion snap wallet?](#how-to-install-ion-snap-wallet)
    - [Install the latest stable version:](#install-the-latest-stable-version)
    - [Install latest candidate version:](#install-latest-candidate-version)
    - [Install latest beta version (launchpad snap builds):](#install-latest-beta-version-launchpad-snap-builds)
    - [Install latest edge version (snapcraft snap):](#install-latest-edge-version-snapcraft-snap)
  - [How to update/upgrade?](#how-to-updateupgrade)
  - [How to UnInstall?](#how-to-uninstall)
  - [Where is ION snap's default datafolder?](#where-is-ion-snaps-default-datafolder)
  - [How do I launch QT/Daemon/CLI/tx?](#how-do-i-launch-qtdaemonclitx)
    - [Launch QT from startmenu](#launch-qt-from-startmenu)
    - [Launch daemon/qt/cli/tx from terminal](#launch-daemonqtclitx-from-terminal)
  - [OS's supported by snap](#oss-supported-by-snap)
  - [Developer notes](#developer-notes)

__Requirements: [snapd](https://docs.snapcraft.io/core/install)__

One ion core build for all Linux and IoT

***Snaps work across many distributions and versions of Linux***. Bundle your dependencies and config, simplifying installs to a single standard command.

# IONCOINCORE SNAP FAQ

Most questions which came up and here we are most frequent questions.

## How to install snapd?

Snap is pre-installed and ready to go on the following:

- [Ubuntu 16.04.4 LTS (Xenial Xerus)](https://www.ubuntu.com/) or later, including [Ubuntu 18.04 LTS (Bionic Beaver)](https://www.ubuntu.com/desktop/features) and [Ubuntu 18.10 (Cosmic Cuttlefish)](https://wiki.ubuntu.com/CosmicCuttlefish/ReleaseNotes).
- Most [recognised Ubuntu flavours](https://wiki.ubuntu.com/DerivativeTeam/Derivatives) built on one of the above Ubuntu releases. An exception is [Lubuntu](https://docs.snapcraft.io/t/installing-snap-on-lubuntu/9965).
- [Solus 3](https://getsol.us/home/) and above.
- [Zorin OS](https://zorinos.com/).

For more info about other distributions please check [installing snapd](https://docs.snapcraft.io/installing-snapd/6735) on [snapcrafts documentation page](https://docs.snapcraft.io/).

## How to install ion snap wallet?

If you run it productive, then please use ***always latest stable version***.

There are 4 different channels:
- stable
- candidate
- beta
- edge

### Install the latest stable version:
  _(this is always current latest release version, built from release tag)_

  `sudo snap install --stable ioncore`

### Install latest candidate version:
  _(this is always current latest release candidate (RC) version, built from release tag or commit)_

  `sudo snap install --candidate ioncore`

### Install latest beta version (launchpad snap builds):
  _(this is launchpad version, built from master and auto built 4 times a day if there are any changes)_
  _(snaps built on launchpad are automaticly released under beta channel)_
  `sudo snap install --beta ioncore`

### Install latest edge version (snapcraft snap):
  _(this is always current latest version built from latest commit on master)
  _(edge builds with snapcraft on each commit to master)_

  `sudo snap install --edge ioncore`

## How to update/upgrade?

Run `sudo snap refresh` to refresh all snaps of your system.

You can specify branch from which you want to refresh, example with --edge: `sudo snap refresh --edge ioncore` 

for more info about usage of snap, run `snap --help`.

## How to UnInstall?

- ##### !!!WARNING!!! backup data folder before uninstalling snap
  if you uninstall, your datafolder `~/snap/ioncore/common/.ioncoin` will be deleted.

  **Please make always a backup of your folder `~/snap/ioncore/common/.ioncoin`** ***before you uninstall ioncore snap***.

  to uninstall, run: `sudo snap remove ioncore`.

## Where is ION snap's default datafolder?

Default data folder for snap builds is located at `~/snap/ioncore/common/.ioncoin`.

If you have never launched snap before, this folder will be created on first start.

## How do I launch QT/Daemon/CLI/tx?

### Launch QT from startmenu

In ubuntu, debian and other linux systems, if you have installed any desktop, then you should find 3 launchers/icons in your start menu:

- Ion Qt
- Ion Qt (Testnet)
- Ion Qt (Regtest)

### Launch daemon/qt/cli/tx from terminal

We used a dot (`.`) insted of a hyphen (`-`) to run ion snap build:

- for main network (_you can use `ion.daemon` --testnet too, but we added `ion.daemon-testnet` for that, check bellow._)
  - `ion.daemon`
  - `ion.cli`
  - `ion.qt`
- for testnet
  - `ion.daemon-testnet`
  - `ion.cli-testnet`
  - `ion.qt-testnet`
- for regtest
  - `ion.daemon-regtest`
  - `ion.cli-regtest`
  - `ion.qt-regtest`

If you want to use ion-tx, then it would be `ion.tx`.

## OS's supported by snap

- [Ion snap builds supports variety of Operating systems](https://snapcraft.io/)
  - [![Install SNAP on Ubuntu](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/ubuntu_128x128.png)](https://docs.snapcraft.io/core/install-debian) ![Install SNAP on Debian](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/debian_128x128.png) [![Install SNAP on Linux Mint](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/mint_128x128.png)](https://docs.snapcraft.io/core/install-linux-mint) [![Install SNAP on Raspbian](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/raspbian_128x128.png)](https://docs.snapcraft.io/core/install-raspbian) [![Install SNAP on ArchLinux](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/archlinux_128x128.png)](https://docs.snapcraft.io/core/install-arch-linux) [![Install SNAP on Fedora](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/fedora_128x128.png)](https://docs.snapcraft.io/core/install-fedora) [![SNAP on OpenWrt](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/openwrit_128x128.png)](https://docs.snapcraft.io/installing-snapd/) ![SNAP on yocto](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/yocto_128x128.png) [![SNAP on openembedded](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/openembed_128x128.png)](https://docs.snapcraft.io/installing-snapd/) [![Install SNAP on OpenSUSE](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/suse_128x128.png)](https://docs.snapcraft.io/t/installing-snap-on-opensuse/8375) [![Install SNAP on manjaro linux](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/manjaro_128x128.png)](https://docs.snapcraft.io/t/installing-snap-on-manjaro-linux/6807) [![Install SNAP on Solus](https://raw.githubusercontent.com/wiki/ioncoincore/ion/assets/images/solus_128x128.png)](https://docs.snapcraft.io/t/installing-snap-on-solus/6803)
  - additional Linux distributions and installation guides ([see all supported distributions](https://docs.snapcraft.io/core/install))
    - [Deepin](https://docs.snapcraft.io/t/installing-snap-on-deepin/6791)
    - [Elementary OS](https://docs.snapcraft.io/t/installing-snap-on-elementary-os/6768)
    - [GalliumOS](https://docs.snapcraft.io/t/installing-snap-on-galliumos/6801)
    - [KDE Neon](https://docs.snapcraft.io/t/installing-snap-on-kde-neon/6792)
    - [Manjaro Linux](https://docs.snapcraft.io/t/installing-snap-on-manjaro-linux/6807)
    - [openSUSE](https://docs.snapcraft.io/t/installing-snap-on-opensuse/8375)
    - [Parrot Security OS](https://docs.snapcraft.io/t/installing-snap-on-parrot-security-os/6810)
    - [Solus](https://docs.snapcraft.io/t/installing-snap-on-solus/6803)
    - [Zorin OS](https://docs.snapcraft.io/t/installing-snap-on-zorin-os/6804)
- Snap builds in Windows 10
  - [How to install Ubuntu/OpenSuse from Microsoft Store](https://fossbytes.com/install-ubuntu-opensuse-windows-store-windows-10/)


## Developer notes

Example of environment variables
```
SNAPCRAFT_IMAGE_INFO={"build_url": "https://launchpad.net/~build.snapcraft.io/+snap/c3aad55ee7697df8fd23da8eaa03f634/+build/527982"}
SNAPCRAFT_PROJECT_VERSION=3.2.99
SNAPCRAFT_EXTENSIONS_DIR=/snap/snapcraft/2725/share/snapcraft/extensions
SNAPCRAFT_PROJECT_GRADE=devel
SNAP_COMMON=/var/snap/snapcraft/common
SNAP_INSTANCE_KEY=
USER=root
CXXFLAGS= -I/build/ioncore/parts/ion/install/usr/include
LD_LIBRARY_PATH=:/build/ioncore/parts/ion/install/lib:/build/ioncore/parts/ion/install/usr/lib:/build/ioncore/parts/ion/install/lib/powerpc64le-linux-gnu:/build/ioncore/parts/ion/install/usr/lib/powerpc64le-linux-gnu
SNAPCRAFT_PART_SRC=/build/ioncore/parts/ion/src
OLDPWD=/root
SNAP_LIBRARY_PATH=/var/lib/snapd/lib/gl:/var/lib/snapd/lib/gl32:/var/lib/snapd/void
HOME=/root
SNAP_USER_DATA=/root/snap/snapcraft/2725
LDFLAGS= -L/build/ioncore/parts/ion/install/lib -L/build/ioncore/parts/ion/install/usr/lib -L/build/ioncore/parts/ion/install/lib/powerpc64le-linux-gnu -L/build/ioncore/parts/ion/install/usr/lib/powerpc64le-linux-gnu
SNAPCRAFT_PARALLEL_BUILD_COUNT=4
SNAP_REVISION=2725
container=lxc
SNAPCRAFT_STAGE=/build/ioncore/stage
SNAPCRAFT_BUILD_INFO=1
SNAPCRAFT_PROJECT_NAME=ioncore
https_proxy=http://10.10.10.1:8222/
http_proxy=http://10.10.10.1:8222/
SNAP_CONTEXT=DsCXBHwfpgfPdnDKQYVrvkw2t28yKVJJC01fYW1X6XB2
SNAP_VERSION=3.3
PKG_CONFIG_PATH=:/build/ioncore/parts/ion/install/usr/share/pkgconfig
SNAP_INSTANCE_NAME=snapcraft
SNAPCRAFT_BUILD_ENVIRONMENT=host
PATH=/build/ioncore/stage/usr/sbin:/build/ioncore/stage/usr/bin:/build/ioncore/stage/sbin:/build/ioncore/stage/bin:/build/ioncore/parts/ion/install/usr/sbin:/build/ioncore/parts/ion/install/usr/bin:/build/ioncore/parts/ion/install/sbin:/build/ioncore/parts/ion/install/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/snap/snapcraft/2725/bin/scriptlet-bin
SNAPCRAFT_PRIME=/build/ioncore/prime
XDG_RUNTIME_DIR=/run/user/0/snap.snapcraft
SNAP_DATA=/var/snap/snapcraft/2725
CFLAGS= -I/build/ioncore/parts/ion/install/usr/include
PERL5LIB=/build/ioncore/stage/usr/share/perl5/
SNAPCRAFTCTL_FEEDBACK_FIFO=/tmp/tmph98t9n6u/call_feedback
SNAPCRAFT_ARCH_TRIPLET=powerpc64le-linux-gnu
LANG=C.UTF-8
SNAPCRAFT_INTERPRETER=/snap/snapcraft/2725/usr/bin/python3
SNAPCRAFT_PART_BUILD=/build/ioncore/parts/ion/build
SNAP_USER_COMMON=/root/snap/snapcraft/common
SNAP_ARCH=ppc64el
GIT_PROXY_COMMAND=/usr/local/bin/snap-git-proxy
SNAP_COOKIE=DsCXBHwfpgfPdnDKQYVrvkw2t28yKVJJC01fYW1X6XB2
CPPFLAGS= -I/build/ioncore/parts/ion/install/usr/include
SHELL=/bin/sh
SNAP_REEXEC=
SNAP_NAME=snapcraft
SNAPCRAFTCTL_CALL_FIFO=/tmp/tmph98t9n6u/function_call
PWD=/build/ioncore/parts/ion/build
SNAP=/snap/snapcraft/2725
SNAPCRAFT_PART_INSTALL=/build/ioncore/parts/ion/install
```