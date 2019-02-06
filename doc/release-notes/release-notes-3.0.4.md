🗺️Ion Core 👛 3.0.4 CE ©️ - 👒 RELEASE 👒  is now available from:

  <https://github.com/ioncoincore/ion/releases>

This is a new minor-revision version release, including various bug fixes and updated documentation.

Please report bugs using the issue tracker at github:

  <https://github.com/ioncoincore/ion/issues>

Recommended Update
==============

🗺️Ion Core 👛 3.0.4 CE ©️ - 👒 RELEASE 👒 is a recommended update for all users. This release contains This release contains a coin supply calculation fix,
 version numbering correction and updated documentation.

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


3.0.4 Change log
=================

Coin supply calculation correction
-------------------------
The coin supply was calculated at the fork point, and the base line number for the recalculation was off.

3.0.3 Change log
=================

Windows masternode.conf port parsing fix
-------------------------
Fixed an issue on Windows wallet with opening masternode ports based on Dash commit 56971f8

Updated DGW start time
-------------------------
Adjusted the DGW start time

Credits
=======

Thanks to everyone who directly contributed to this release:
- Formax
- CEVAP
- Ceforce
- Atomsmasher
- Coinkiller

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
