🗺️Ion Core 👛 3.0.2 CE ©️ - 👒 RELEASE 👒  is now available from:

  <https://github.com/ioncoincore/ion/releases>

This is a new minor-revision version release, including various bug fixes and
performance improvements, as well as updated translations.

Please report bugs using the issue tracker at github:

  <https://github.com/ioncoincore/ion/issues>

Recommended Update
==============

🗺️Ion Core 👛 3.0.2 CE ©️ - 👒 RELEASE 👒 is a recommended, semi-mandatory update for all users. This release contains transaction creation bug fixes for xION spends, automint calculation adjustments, and other various updates/fixes.

xION spending requires this update.

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely shut down (which might take a few minutes for older versions), then run the installer (on Windows) or just copy over /Applications/Ion-Qt (on Mac) or iond/ion-qt (on Linux).

Compatibility
==============

🗺️Ion Core 👛 is extensively tested on multiple operating systems using
the Linux kernel, macOS 10.8+, and Windows Vista and later.

Microsoft ended support for Windows XP on [April 8th, 2014](https://www.microsoft.com/en-us/WindowsForBusiness/end-of-xp-support),
No attempt is made to prevent installing or running the software on Windows XP, you
can still do so at your own risk but be aware that there are known instabilities and issues.
Please do not report issues about Windows XP to the issue tracker.

🗺️Ion Core 👛 should also work on most other Unix-like systems but is not
frequently tested on them.

### :exclamation::exclamation::exclamation: MacOS 10.13 High Sierra :exclamation::exclamation::exclamation:

**Currently there are issues with the 3.0.x gitian releases on MacOS version 10.13 (High Sierra), no reports of issues on older versions of MacOS.**


Notable Changes
===============

xION (_zerocoin for ion_)
-------------------------
We have now zerocoin into ion. More info about what it is and how to use it will follow in announcements and further release infos.

Snap/Snapcraft builds
----------------------------
Snapcraft is enabled and it can be simply installed by

`sudo snap install --edge ion`

([Don’t have snapd installed?](https://docs.snapcraft.io/core/install))

Supported architectures: `i386, armhf, amd64`

Snap supported OS and installation instructions:

  - [Arch Linux](https://docs.snapcraft.io/core/install-arch-linux)
  - [Debian](https://docs.snapcraft.io/core/install-debian)
  - [Fedora](https://docs.snapcraft.io/core/install-fedora)
  - [Gentoo](https://docs.snapcraft.io/core/install-gentoo)
  - [Linux Mint](https://docs.snapcraft.io/core/install-linux-mint)
  - [Manjaro](https://docs.snapcraft.io/core/install-manjaro)
  - [OpenEmbedded/Yocto](https://docs.snapcraft.io/core/install-oe-yocto)
  - [openSUSE](https://docs.snapcraft.io/core/install-opensuse)
  - [OpenWrt](https://docs.snapcraft.io/core/install-openwrt)
  - [Solus](https://docs.snapcraft.io/core/install-solus)
  - [Ubuntu](https://docs.snapcraft.io/core/install-ubuntu)


Functions renamed
-----------------
Stashedsend is now Swift-X

New algorithm
-------------
We dropped MIDAS and will use DGW. More info will follow.

Automint
--------
Autominiting with zerocoin. More info will follow.

New look and design
-------------------
We have new look and desing, currently it is a dirty version. It includes new GUI layout, new colors.

Performance
-----------
Current source base is much faster and cleaner than ion's previous one. It uses all cpu's and there are 
no performance issues which we could observe, it is just much faster then previous source base.

BIP38
-----
We have BIP38 including a tool with password encryption and decrpytion features

Blockexplorer
-------------
We finaly have built in blockexplorer which works on all ion's networks.

User friendly
-------------
There are some new features which improve usability as well as user experience in general. More info to follow.

Auto Wallet Backup
---------------------
In addition to the automatic wallet backup that is done at each start of the client, a new automatic backup function has been added that will, by default, create a backup of the wallet file during each xION mint operation (xION spends which re-mint their change are also included in this). This functionality is controlled by the `-backupxion` command-line option, which defaults to `1` (enabled, auto-backup).

Users that wish to prevent this behavior (not recommended) can pass `-backupxion=0` at the command-line when starting the client, or add `backupxion=0` to their `ioncoin.conf` file.

xION Automint Calculations
---------------------
A bug in the automint calculations was made apparent on mainnet when block times exceeded expectations, resulting in xION mint transactions that were in an unconfirmed state to still be treated as if they had never been minted. This caused automint to effectively mint more than what was intended.

xION Spending Fix
---------------------
The size of xION spend transactions is knowingly larger than normal transactions, and while this was expected, a much stricter check against the scriptsig size is used for mainnet, causing the transactions to be rejected by the mempool, and thus not being packaged into any blocks.

xION Transaction Recovery
---------------------
Due to the aforementioned issue with xION spending, users may find that their attempted spends are now conflicted and xION balances are not represented as expected. "Recovery" of these transactions can be done using the following methods:

1. GUI:

   The Privacy tab has the `Reset` and `Rescan` buttons that can be used to restore these mints/spends from a state of being marked as unavailable.

2. RPC:

   The RPC commands `resetspentzerocoin` and `resetmintzerocoin` are the command-line counterparts to the above, and can be used by users that do not use the GUI wallet.

RPC Changes
---------------------
The `bip38decrypt` command has had it's parameter order changed to be more consistent with it's counterpart. The command now expects the Ion address as it's first parameter and the passphrase as it's second parameter.

Bip38 Compatibility With 3rd Party Tools
---------------------
The in-wallet bip38 encryption method was leaving the final 4 bytes of the encrypted key blank. This caused an incompatibility issue with 3rd party tools like the paper wallet generators that could decrypt bip38 encrypted keys. Cross-tool compatibility has now been restored.

3.0.2 Change log
=================

This release is a fork to the old chain. Detailed release notes follow.
We dropped MIDAS and use DGW as well as some other changes. Previous old version
was based on old projects which were not updated. One of our main goals for v3 release
was to get closer to bitcoin's source and update in general sources to some newer
and cleaner codebase then it was previously. We forked from PIVX which is better
maintenanced then previous releases of 🗺️Ion Core 👛 which are based on obsolete code.
In this version everything is new, one big feature iz xION which iz zerocoin for
ion. Port and other settings remain same. Please foolow our wiki for more information
about how to backup your wallet/keys and upgrade to new wallet as well as recovery paths
and detailed explanations of how to use new code. One big difference is finally restricting
in better was single mode masternode, as multi mode is not usefull within larger networks.


Notable changes of source for the fork
======================================
### RPC and other APIs
- #275 `059aaa9` [RPC] Change Parameter Order of bip38decrypt (presstab)

### P2P Protocol and Network Code
- #286 `85c0f53` [Main] Change sporkDB from smart ptr to ptr. (presstab)
- #292 `feadab4` Additional checks for double spending of zPiv serials. (presstab)

### Wallet
- #271 `5e9a086` [Wallet] Remove unused member wallet in UnlockContext inner class (Jon Spock)
- #279 `e734010` Add -backupzpiv startup flag. (presstab)
- #280 `fdc182d` [Wallet] Fix zPiv spending errors. (presstab)
- #282 `310f216` [Wallet] Count pending zPiv balance for automint. (presstab)
- #290 `004d7b6` Include both pending and mature zerocoins for automint calculations (presstab)

### GUI
- #268 `bc63f24` [GUI/RPC] Changed bubblehelp text + RPC startmasternode help text fixed (Mrs-X)
- #269 `5466a9b` Check if model is valid before using in transactionView (Jon Spock)
- #270 `bd2328e` [Qt] Make lock icon clickable to toggle wallet lock state (Fuzzbawls)
- #273 `f31136e` [Qt] Fix UI tab order and shortcuts (Mrs-X)
- #287 `74a1c3c` [Qt] Don't allow the Esc key to close the privacy tab (Fuzzbawls)
- #291 `cb314e6` [Qt] zPiv control quantity/amount fixes (rejectedpromise)

### Miscellaneous
- #266 `2d97b54` [Scripts] Fix location for aarch64 outputs in gitian-build.sh (Fuzzbawls)
- #272 `958f51e` [Minting] Replace deprecated auto_ptr. (presstab)
- #276 `03f14ba` Append BIP38 encrypted key with an 4 byte Base58 Checksum (presstab)
- #288 `2522aa1` Bad CBlockHeader copy. (furszy)

Credits
=======

Thanks to everyone who directly contributed to this release:
- Formax
- CEVAP

And to source contributors which provided base for this release with their project:
- Fuzzbawls
- Jon Spock
- Mrs-X
- furszy
- presstab
- rejectedpromise
- Warrows

As well as everyone that helped translating on [Transifex](https://www.transifex.com/projects/p/ion/).

Setting up the Gitian image
======================

Credentials
--------------
user: `gitianuser`
pass: `cevap`

user: `root`
pass: `cevap`

On your machine edit or create `~/.ssh/config` and add:

```
Host gitian
    HostName localhost
    Port 22222
    User gitianuser
```

Open a new terminal tab and enter (_check your .ssh folder for file name, id_rsa.pub and id_ecdsa.pub are defaults_):

```
scp ~/.ssh/id_rsa.pub gitian:.ssh/authorized_keys
```

Now connect to your gitian with: `ssh gitian`, no password will be required for ssh connection.

Now build base vm:

```
cd gitian-builder
bin/make-base-vm --lxc --arch amd64 --suite trusty
```
There will be a lot of warnings printed during the build of the image. These can be ignored.

**Note**: When sudo asks for a password, enter the password for the user gitianuser not for root.

Getting and building the inputs
--------------------------------------
At this point you have two options, you can either use the automated script (found in https://github.com/ioncoincore/ion/blob/master/contrib/gitian-build.sh, only works in Debian/Ubuntu) or you could manually do everything by following this guide. If you are using the automated script, then run it with the --setup command. Afterwards, run it with the --build command (example: contrib/gitian-build.sh -b signer 3.0.2). Otherwise ignore this.

Follow the instructions in https://github.com/ioncoincore/ion/blob/master/doc/release-process.md in the bitcoin repository under 'Fetch and create inputs' to install sources which require manual intervention. Also optionally follow the next step: 'Seed the Gitian sources cache and offline git repositories' which will fetch the remaining files required for building offline.

_**Note**: please use our links here, I left cevap as I do not want to remove it later_

That's it, follow release notes and how to build on our repo

Build with gitian
============

Signer is key, please use your github public key _(or [create new gpg key](https://help.github.com/articles/generating-a-new-gpg-key/) for gitian only and [add it to your account](https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/), the same goes for SSH key ([create](https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/) | [add](https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/)_). To show your key, run in terminal: `gpg --list-secret-keys --keyid-format LONG`

The output will show you key/keys, like this:
```
tor@tor ~ $ gpg --list-secret-keys --keyid-format LONG
/home/tor/.gnupg/secring.gpg
----------------------------
sec   3072R/49464B32BA6683BA 2017-03-13
uid                          developer (dev@i2pmail.org) <dev@i2pmail.org>
ssb   3072R/78E10152BEC6C3C6 2017-03-13
```


Take the key from sec line,

  sec   3072R/**49464B32BA6683BA** 2017-03-13

which would be in this case `49464B32BA6683BA`. This is your SIGNER.

GPG does not have enough entropy
----------------------------------------------
If you use high encryption and set your key to 4096bits, you might get some message similar to this `GPG does not have enough entropy`.

One of workarounds would be package for generating entropy called haveged. Install `haveged` and `rng-tools` by running:
`sudo apt-get install -y haveged rng-tools`

then create entropy with:
```
# run it with sudo if it requires root access
cat /dev/random | rngtest -c 1000
``` 

Now you can create your key with `gpg --gen-key`

Gist gitian build scripts
----------------------------
**Note**: Please change SIGNER to your key and version to desired version, in current release it is version 3.0.2, in future releases gist will be updated.

If you use scripts, after wget has downloaded the script, run `sed -i 's/49464B32BA6683BA/YOURGPGKEY/g''  and replace `YOURGPGKEY` with your LONG Key ID. The same can be done with version.
 - Linux only: [build offline](https://gist.github.com/cevap/9d7ef39be185cc07c3d0a9b33da2fba5)
 - Windows only: [build offline](https://gist.github.com/cevap/5d6ac38f6e8530d45ab31499bc3a62ff)
 - MacOS only (without HighSierra)[build offline](https://gist.github.com/cevap/a5a90607da3a9b058b8c0aea20fdd75a)

Setup **signer** and **version**/branch
-------------------------------------------------

```
cd ./ion
export SIGNER="49464B32BA6683BA" # Replace with your Key
export VERSION=3.0.2 # github branch
git fetch
git checkout v${VERSION}
cd ..

# update signature
cd ./gitian.sigs
git pull
cd ..

# update gitian builder
cd ./gitian-builder
git pull
cd ..

# Fetch and create inputs: (first time, or when dependency versions change)
cd ./gitian-builder
mkdir -p inputs
wget -P inputs https://github.com/cevap/osslsigncode/releases/download/v1.7.1/osslsigncode-Backports-to-1.7.1.patch
wget -P inputs -O inputs/v1.7.1.tar.gz https://github.com/cevap/osslsigncode/archive/v1.7.1.tar.gz
wget -P inputs https://github.com/cevap/MacOSX-SDKs/releases/download/MacOSX10.11.sdk-trusty/MacOSX10.11.sdk.tar.gz
cd ..

# prebuild ion dependencies
cd ./gitian-builder
make -C ../ion/depends download SOURCES_PATH=`pwd`/cache/common
cd ..
```

Building offline
------------------

```
cd ./gitian-builder

# Build offline for linux
./bin/gbuild --url ion=/home/gitianuser/ion,signature=/home/gitianuser/gitian.sigs --num-make 2 --memory 3000 --commit ion=v${VERSION} ../ion/contrib/gitian-descriptors/gitian-linux.yml

# Sign for linux
./bin/gsign --signer "$SIGNER" --release ${VERSION}-linux --destination ../gitian.sigs/ ../ion/contrib/gitian-descriptors/gitian-linux.yml
mv build/out/ion-*.tar.gz build/out/src/ion-*.tar.gz ../

# Build offline for windows
./bin/gbuild --url ion=/home/gitianuser/ion,signature=/home/gitianuser/gitian.sigs --num-make 2 --memory 3000 --commit ion=v${VERSION} ../ion/contrib/gitian-descriptors/gitian-win.yml

# Sign for windows
./bin/gsign --signer "$SIGNER" --release ${VERSION}-win-unsigned --destination ../gitian.sigs/ ../ion/contrib/gitian-descriptors/gitian-win.yml
mv build/out/ion-*-win-unsigned.tar.gz inputs/ion-win-unsigned.tar.gz
mv build/out/ion-*.zip build/out/ion-*.exe ../

# Build offline for mac os
./bin/gbuild --url ion=/home/gitianuser/ion,signature=/home/gitianuser/gitian.sigs --num-make 2 --memory 3000 --commit ion=v${VERSION} ../ion/contrib/gitian-descriptors/gitian-osx.yml

# Sign for macos
./bin/gsign --signer "$SIGNER" --release ${VERSION}-osx-unsigned --destination ../gitian.sigs/ ../ion/contrib/gitian-descriptors/gitian-osx.yml
mv build/out/ion-*-osx-unsigned.tar.gz inputs/ion-osx-unsigned.tar.gz
mv build/out/ion-*.tar.gz build/out/ion-*.dmg ../
cd ..
```


Building online
---------------

```
# Build online for linux
./bin/gbuild --num-make 2 --memory 3000 --commit ion=v${VERSION} ../ion/contrib/gitian-descriptors/gitian-linux.yml

# Sign for linux
./bin/gsign --signer "$SIGNER" --release ${VERSION}-linux --destination ../gitian.sigs/ ../ion/contrib/gitian-descriptors/gitian-linux.yml
mv build/out/ion-*.tar.gz build/out/src/ion-*.tar.gz ../

# Build online for windows
./bin/gbuild --num-make 2 --memory 3000 --commit ion=v${VERSION} ../ion/contrib/gitian-descriptors/gitian-win.yml

# Sign for windows
./bin/gsign --signer "$SIGNER" --release ${VERSION}-win-unsigned --destination ../gitian.sigs/ ../ion/contrib/gitian-descriptors/gitian-win.yml
mv build/out/ion-*-win-unsigned.tar.gz inputs/ion-win-unsigned.tar.gz
mv build/out/ion-*.zip build/out/ion-*.exe ../

# Build online for mac os
./bin/gbuild --num-make 2 --memory 3000 --commit ion=v${VERSION} ../ion/contrib/gitian-descriptors/gitian-osx.yml

# Sign for macos
./bin/gsign --signer "$SIGNER" --release ${VERSION}-osx-unsigned --destination ../gitian.sigs/ ../ion/contrib/gitian-descriptors/gitian-osx.yml
mv build/out/ion-*-osx-unsigned.tar.gz inputs/ion-osx-unsigned.tar.gz
mv build/out/ion-*.tar.gz build/out/ion-*.dmg ../
cd ..
```
