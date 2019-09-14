Ion Core integration/staging repository
=======================================
[![GitHub license](https://img.shields.io/github/license/ioncoincore/ion.svg?style=social)](https://github.com/ioncoincore/ion) ![](https://img.shields.io/github/contributors-anon/ioncoincore/ion.svg?style=social) [![GitHub issues](https://img.shields.io/github/issues/ioncoincore/ion.svg?style=social)](https://github.com/ioncoincore/ion/issues) [![GitHub forks](https://img.shields.io/github/forks/ioncoincore/ion.svg?style=social)](https://github.com/ioncoincore/ion/network) [![GitHub stars](https://img.shields.io/github/stars/ioncoincore/ion.svg?style=social)](https://github.com/ioncoincore/ion/stargazers) 
[![GitHub version](https://badge.fury.io/gh/ioncoincore%2Fion.svg)](https://badge.fury.io/gh/ioncoincore%2Fion) [![Build Status](https://travis-ci.org/ioncoincore/ion.svg?branch=master)](https://travis-ci.org/ioncoincore/ion) [![Snap Status](https://build.snapcraft.io/badge/ioncoincore/ion.svg)](https://build.snapcraft.io/user/ioncoincore/ion) ![Commits since latest version](https://img.shields.io/github/commits-since/ioncoincore/ion/latest.svg)
![Top Language](https://img.shields.io/github/languages/top/ioncoincore/ion.svg?color=blue) ![Languages amount](https://img.shields.io/github/languages/count/ioncoincore/ion.svg) ![Commit activity](https://img.shields.io/github/commit-activity/m/ioncoincore/ion.svg) ![Last commit](https://img.shields.io/github/last-commit/ioncoincore/ion/master.svg)

**Latest release** | **Contact us/Chat with us** | **ionomy.com homepage status** |
 :-: | :-: | :-: |
[![Latest release](https://img.shields.io/github/release/ioncoincore/ion.svg)](https://github.com/ioncoincore/ion/releases/latest) ![Release date](https://img.shields.io/github/release-date/ioncoincore/ion.svg) | [![Twitter](https://img.shields.io/twitter/url/https/github.com/ioncoincore/ion.svg?style=social)](https://twitter.com/intent/tweet?text=Wow:&url=https%3A%2F%2Fgithub.com%2Fioncoincore%2Fion) [![Chat on Discord](https://img.shields.io/discord/308323056592486420.svg?logo=discord)](https://discord.gg/vuZn7gC) ![Official Encrypted Support (Matrix)](https://img.shields.io/matrix/ionsupportgeneral:matrix.provenstack.com.svg?server_fqdn=matrix.provenstack.com) | [![](https://img.shields.io/website/https/ionomy.com.svg?down_color=darkred&down_message=ionomy.com%20is%20offline&style=for-the-badge&up_color=green&up_message=ionomy.com%20is%20online)](https://ionomy.com)

_If you want to encrypt your email/files, please use public pgp key provided below._
![Keybase PGP](https://img.shields.io/keybase/pgp/ioncoincore.svg?style=flat)

## Installation methods

  We offer different installation and distribution methods covering most user needs.
  Below you can see

#### Install via SNAP (_preffered method for linux users_)

_For full information about usage and possible installation methods and Branches, please check out [Ioncore Snap Builds](snap/README.md#ioncore-snap-builds)_

    sudo snap install ioncore

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/ioncore)

#### Download and install latest stable release binaries (_preffered method for windows and mac os users_)

[![Latest release](https://img.shields.io/github/release/ioncoincore/ion.svg)](https://github.com/ioncoincore/ion/releases/latest) ![Latest stable Release](https://img.shields.io/github/downloads/ioncoincore/ion/latest/total.svg?style=social)

_For full information about usage and possible installation methods and Branches, please check out [Build and install ion (all OS)](../../tree/master/doc)_

#### Build, compile and install from source (_for advanced users_)

- [Build, compile and install documenattion](../../tree/master/doc#building)


## Ion sources:

We forked from [PIVX](https://github.com/PIVX-Project/PIVX) and integrated ION's specific features into the PivX codebase.

By doing so, we connect to an enthusiastic and active community - leaving behind old Ion code that inherits from less actively developed and maintaned code. Our main sources are now derived from:

[![](https://github.com/PIVX-Project/PIVX/raw/master/share/pixmaps/bitcoin64.png)](https://github.com/PIVX-Project/PIVX) | [![](https://github.com/dashpay/dash/raw/master/share/pixmaps/dash32.png)](https://github.com/dashpay/dash) | [![](https://github.com/bitcoin/bitcoin/raw/master/share/pixmaps/bitcoin32.png)](https://github.com/bitcoin/bitcoin)
:-: | :--: | :-: |


More information at [ionomy.com](https://www.ionomy.com) Visit our ANN thread at [BitcoinTalk](https://bitcointalk.org/index.php?topic=1443633.7200)

## Coin Specs

Coin specifications ||
:------------ | :---:
Algorithm | Quark |
Retargeting Algorithm | DGW |
Difficulty Retargeting | Every Block
Max Coin Supply | 48,035,935.4 ION
Premine | 16,400,000 ION*

_*16,629,951 Ion Premine was burned in block [1](https://chainz.cryptoid.info/ion/block.dws?000000ed2f68cd6c7935831cc1d473da7c6decdb87e8b5dba0afff0b00002690.htm)_

### Reward Distribution

#### Genesis block

| Block Height | Reward Amount | Notes |
 ------------: | ------------: | :---: |
1 | 16,400,000 ION | Initial Pre-mine |

### PoW Rewards Breakdown

Block Height | Masternodes | Miner | Total |
 ----------: | ----------: | ----: | ----: |
2-454 | 50% (11.5 ION) | 50% (11.5 ION) | 10,419 ION |

### PoS/PoW Rewards Breakdown

Block Height | Masternodes | Miner | Budget |
 ----------: | ----------: | ----: | -----: |
455-1000 | 50% (11.5 ION) | 50% (11.5 ION)| 12,558 ION |

### PoS Rewards Breakdown

Block Height | Masternodes | Miner | Budget |
 ----------: | ----------: | ----: | -----: |
1001-125147 | 50% (11.5 ION) | 50% (11.5 ION) | 2,855,381 ION |
125148-550001 | 50% (8.5 ION) | 50% (8.5 ION) | 7,222,518 ION |
550002-551441 | 50% (0.01 ION) | 50% (0.01 ION) | 28.8 ION |
551442-570063 | 50% (8.5 ION) | 50% (8.5 ION) | 316,574 ION |
570064-1013539 | 50% (5.75 ION) | 50% (5.75 ION) | 5,099,974 ION |
1013540-1457015 | 50% (2.875 ION) | 50% (2.875 ION) | 2,549,987 ION |
1457016-3677391 | 50% (0.925 ION) | 50% (0.925 ION) | 4,107,695.6 ION |
3677392-50981391 | 50% (0.1 ION) | 50% (0.1 ION) | 9,460,800 ION |

## Ion Core FAQ/Help
_get support/chat with us or send your request per [Email](mail:support@ionomy.com). You can also join our discord or encrypted chat on matrix._
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ioncoincore/ion.svg?style=social)](https://twitter.com/intent/tweet?text=Wow:&url=https%3A%2F%2Fgithub.com%2Fioncoincore%2Fion) [![Chat on Discord](https://img.shields.io/discord/308323056592486420.svg?logo=discord)](https://discord.gg/vuZn7gC) ![Official Encrypted Support (Matrix)](https://img.shields.io/matrix/ionsupportgeneral:matrix.provenstack.com.svg?server_fqdn=matrix.provenstack.com)

- [Documentation](../../tree/master/doc)
  - [Setup Ion](../../tree/master/doc#setup)
  - [Running Ion Core](../../tree/master/doc#running)
    - [Windows](https://github.com/ioncoincore/ion/tree/master/doc#windows)
    - [Unix](https://github.com/ioncoincore/ion/tree/master/doc#unix)
    - [OSX](https://github.com/ioncoincore/ion/tree/master/doc#osx)
- [Ion Core CE Wiki](../../wiki)
  - [Accounts-Explained](../../wiki/Accounts-Explained)
  - [API Call list](../../wiki/API-Calls-List)
  - [API-Reference-JSON-RPC](../../wiki/API-Reference-JSON-RPC)
  - [Data-Directory](../../wiki/Data-Directory)
- External ressources
  - [Ionomy.com](https://ionomy.com)
    - [Telegram](https://t.me/ionomy)
    - [Twitter](https://twitter.com/ionomics)
    - [ionomy github](https://github.com/ionomy)
    - [reddit](https://www.reddit.com/r/ionomy/)
    - [facebook](https://facebook.com/ionomy)

## Documentation

- [Client Documentation](../../tree/master/doc)
- [Technical documentation (doxygen)](techdocu.ioncore.xyz)
