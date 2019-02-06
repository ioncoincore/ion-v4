Ion Core version 3.0.5 is now available from:

  <https://github.com/ioncoincore/ion/releases>

This is a new minor version release, with various bugfixes.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/ioncoincore/ion/releases>

Recommended Update
==================

Ion Core version 3.0.5 is a recommended update for all users. This release
contains new hardcoded checkpoints to guard against forks in the network.

If your client is only finding limited peers or sending and receiving coins
aren't reaching their destination you may need to upgrade to this version and
perform a resync of the blockchain.

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Ion-Qt` (on Mac)
or `iond`/`ion-qt` (on Linux).

Compatibility
=============

Ion Core is extensively tested on multiple operating systems using
the Linux kernel, macOS 10.8+, and Windows Vista and later. Windows XP is not supported.

Ion Core should also work on most other Unix-like systems but is not
frequently tested on them.

3.0.5 change log
----------------

- `fd5298c` Update README.md (Cevap Master)
- `e53d2de` Bump version number to 3.0.4 (FornaxA)
- `f8a7e1c` Update coin supply amount (FornaxA)
- `4c19e64` Add release notes (FornaxA)
- `784d3a1` Add checkpoint before merging, 552317, ref pull: #3 (cevap)
- `6893a90` Update README.md (Cevap Master)
- `606f97c` Update travis and snap, add default dir patch (cevap)
- `4cecdaf` remove unmarked junk which breaks snapcraft building (cevap)
- `663643f` Fix: snap - default data dir patch (cevap)
- `0789160` Fix: check doc script failed due to misspelled backupxION instead of backupxion (cevap)
- `971eb5a` cleaned up artworks, added code of conduct (cevap)
- `fd46ab0` Fix copyright header scripts (cevap)
- `8768fc8` Add assets: screenshots of QT (cevap)
- `ca35635` Snapcraft 256x256 logo in shared folder (cevap)
- `3e2e48b` Update debian sources for: new icons, some minor text fixes (cevap)
- `2310e84` Redimensioned svg (cevap)
- `f19036d` Add testnet, regtest and unittest pixmaps (cevap)
- `c46bd54` Add new icon and its source for main network (cevap)
- `cc4b053` Add 2 isns related scripts (cevap)
- `12cb98c` New icons and its sources for testnet, regtest and unittest (cevap)
- `44fd4c2` Updated RPC tests, ref #8 (cevap)
- `845408d` Remove warning during compilation, fixed #9 (cevap)
- `44e16ef` Replace all occurencies of ION-Qt with Ion-Qt (cevap)
- `e36f97a` Add splashscreens, fixed #10 (cevap)
- `1a08917` Rename all occurencies from ' ION ' to ' Ion ' (cevap)
- `d6cf121` Iconn: small fixes, ref: #7 (cevap)
- `5491b06` Ref #8 - Add tx pair to ordered list when adding it to the wallet (FornaxA)
- `8ea377a` Create CODE_OF_CONDUCT.md (Cevap Master)
- `67b8736` Sign code of conduct (cevap)
- `6439a59` Rename bitcoin.org to ioncore.xyz, ref: #13 (cevap)
- `941f0c9` Fix: travis broken due to SDK url replaced, fixing (cevap)
- `d43c6c0` revert failure by wrong commit, ref #13 (cevap)
- `fa72830` Change urls for osslsigncode v1.7.1 to use from sources from our repo, ref: #13 (cevap)
- `0418712` Add additional icons to snapcraft build (cevap)
- `8e029bf` Snap (#30) (Cevap Master)
- `3b2434c` Snap builds fix bad commit (cevap)
- `e17311c` Ionian Documentation (#23) (ckti)
- `9d05d8e` Ion Build Documaentation for Raspian (#24) (ckti)
- `ae0a10e` Update Travis build checks (#26) (Mitchell Cash)
- `0da0dd8` Add ability to install man pages via `make install` (#27) (Mitchell Cash)
- `e93a698` Update checkpoints to guard against forks in the network (Mitchell Cash)
- `680ffb5` Update configure.ac version on master and set release to false (Mitchell Cash)

Credits
=======

Thanks to everyone who directly contributed to this release:

- cevap
- Cevap Master
- ckti
- FornaxA
- Mitchell Cash
