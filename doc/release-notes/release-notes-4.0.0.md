## ION Core version 4.0.0 is now available  

Download at: https://github.com/ioncoincore/ion/releases

This is a new major version release, including various bug fixes, performance improvements, implementation of the Atomic Token Protocol (ATP), as well as updated translations.

Please report bugs using the issue tracker at github: https://github.com/ioncoincore/ion/issues

### Mandatory Update
___  

ION Core v4.0.0 is a mandatory update for all users. This release contains new consensus rules and improvements that are not backwards compatible with older versions. Users will have a grace period of up to two week to update their clients before enforcement of this update is enabled - a grace period that will end at block 1320000 the latest.

### How to Upgrade
___
If you are running an older version, shut it down. Wait until it has completely shut down (which might take a few minutes for older versions), then run the installer (on Windows) or just copy over /Applications/ION-Qt (on Mac) or iond/ion-qt (on Linux).

### Compatibility
ION Core is extensively tested on multiple operating systems using the Linux kernel, macOS 10.8+, and Windows Vista and later.

Microsoft ended support for Windows XP on April 8th, 2014, No attempt is made to prevent installing or running the software on Windows XP, you can still do so at your own risk but be aware that there are known instabilities and issues. Please do not report issues about Windows XP to the issue tracker.

ION Core should also work on most other Unix-like systems but is not frequently tested on them.

#### Mac OSX High Sierra  
Currently there are issues with the 4.x gitian release on MacOS version 10.13 (High Sierra), no reports of issues on older versions of MacOS.
### Atomic Token Protocol (ATP)
_____

**Introduction:**  

As part of the integration of game development functionality and blockchain technology, the ION community chose to adopt a token system as part of its blockchain core. The community approved proposal IIP 0002 was put to vote in July 2018, after which development started. Instead of developing a solution from scratch, the team assessed a number of proposals and implementations that were currently being worked on for other Bitcoin family coins. Selection criteria were:

* Fully open, with active development
* Emphasis on permissionless transactions
* Efficient in terms of resource consumption
* Simple and elegant underlying principles 

The ATP system implemented is based on the Group Tokenization proposal by Andrew Stone / BU.

**References:**

[GROUP Tokenization specification by Andrew Stone](https://docs.google.com/document/d/1X-yrqBJNj6oGPku49krZqTMGNNEWnUJBRFjX7fJXvTs/edit#heading=h.sn65kz74jmuf)  
[GROUP Tokenization reference implementation for Bitcoin Cash](https://github.com/gandrewstone/BitcoinUnlimited/commits/tokengroups)  

For the technical principles underlying ION Group Tokenization, the above documentation is used as our standard.

ION developers fine tuned, extended and customized the Group Tokenization implementation. This documentation aims to support the ION community in:

* Using the ION group token system
* Creating additional tests as part of the development process
* Finding new use cases that need development support

### Noteable Changes
______

##### Zerocoin
- Switch to public spending of xION v2, allowing users to spend their zerocoin back to ION. All users are advised to spend zerocoin as soon as possible.
- Minting of new zerocoin remains disabled
- Zerocoin staking remains disabled

##### Protocol change
- A new 256-bit modifier for the proof of stake protocol has been defined, CBlockIndex::nStakeModifierV2.
It is computed at every block, by taking the hash of the modifier of previous block along with the coinstake input. Changeover enforcement of this new modifier is set to occur at block 1320000.
- Zero fee transactions are no longer accepted by the mempool.
- Maximum size of data in data carrier transactions is increased to 184 bytes to allow storage of token description data.

### New RPC Commands
__________

#### Tokens

`configuremanagementtoken "ticker" "name" decimalpos "description_url" description_hash ( confirm_send )  `  
`configuretoken "ticker" "name" ( decimalpos "description_url" description_hash ) ( confirm_send )  `  
`createtokenauthorities "groupid" "ionaddress" authoritylist  `  
`droptokenauthorities "groupid" "transactionid" outputnr [ authority1 ( authority2 ... ) ] `   
`getsubgroupid "groupid" "data"  `  
`gettokenbalance ( "groupid" )  `  
`listtokenauthorities "groupid"`    
`listtokenssinceblock "groupid" ( "blockhash" target-confirmations includeWatchonly ) `   
`listtokentransactions "groupid" ( count from includeWatchonly ) `   
`melttoken "groupid" quantity  `  
`minttoken "groupid" "ionaddress" quantity  `  
`sendtoken "groupid" "address" amount  `  
`tokeninfo [list, all, stats, groupid, ticker, name] ( "specifier " )  `  
`scantokens <action> ( <scanobjects> ) `

#### Masternodes
`createmasternodekey `  
`getmasternodeoutputs `  
`getmasternodecount`  
`getmasternodeoutputs`  
`getmasternodescores ( blocks )`  
`getmasternodestatus`  
`getmasternodewinners ( blocks "filter" )`  
`startmasternode "local|all|many|missing|disabled|alias" lockwallet ( "alias" )`
`listmasternodeconf ( "filter" )`  
`listmasternodes ( "filter" )`


### Deprecated RPC Commands
___
#### Masternodes
`masternode count`  
`masternode current`  
`masternode debug`  
`masternode genkey`  
`masternode outputs`  
`masternode start`  
`masternode start-alias`  
`masternode start-<mode>`  
`masternode status`  
`masternode list`  
`masternode list-conf`  
`masternode winners`  


### 4.0.0 Change log
___
Andrew Stone <g.andrew.stone@gmail.com> (20):
- `5ccc6504` Create a shared library to make creating wallets easier.
- `460c4259` Refactor Script interpreter as a "virtual machine" encapsulated by a class.
- `83f66e8d` OP_GROUP consensus-only implementation
- `3f08edf9` add proof that token desc document hasn't changed
- `ed995b35` enforce 20 or 32 byte group identifier sizes
- `8a44d52a` test copy-paste issue -- need to reference value of correct tx
- `f66783d2` add token processing to wallet and RPC commands to create groups, mint tokens, send tokens, and melt them back to BCH
- `387df130` added RPC command information
- `d983670e` add discussion distilled from IMs and opcode retirement section
- `1d874b0b` token balance RPC returns all group balances
- `6f0b20f2` add quantity to OP_GROUP, allow limited quantity tokens via a single mint operation, format c++ and python files as per our style and PEP8 recommendations
- `7b5b5918` fix token listsinceblock param interpretation error. Add group output reporting to gettransaction
- `cbb7db60` token groups with authority UTXOs
- `86563f4a` convert wallet to use group authorities
- `32f9a7d9` wallet RPC test
- `86bffb6e` add authority RPC call to create child authorities, rename Controller to Authority
- `84e9e1a5` fix and add tests for authority mixing rule
- `8ce1c44c` add subgroup functionality. cashaddr is strangely requiring certain lengths when one of its valuable features is to allow any length. version length 7 was changed to mean any length, not 512 bytes
- `9cef826f` switch ionaddr to only ignore length 7 if group type
- `7f8c9c83` implement OP_RETURN token description data

Cevap Master <dev@i2pmail.org> (3):
- `1b375206` [Build system][GUI][docs] - refactor build process for snap, dpkg (#151)
- `4240f2ae` [maintenance] minor fixes debian snap (#152)
- `06f759e5` maintenance, bug fixes, new testnet, new regtest, fake stake fixed and more (#141)

Cory Fields <cory-nospam-@coryfields.com> (1):
- `7a5ccf82` Consensus: Refactor: Decouple CValidationState from main::AbortNode()

Cozz Lovan <cozzlovan@yahoo.com> (1):
- `6f8e9bb7` Subtract fee from amount

Cryptarchist <cryptarchist@gmail.com> (1):
- `c0d63558` Improve the listtransactionrecords RPC command

FornaxA <25762277+FornaxA@users.noreply.github.com> (2):
- `91ae7095` Upstream upgrades: maintainence, bug fixes, zerocoin public spends (#3)
- `0383fda0` Upstream upgrades: maintainence, bug fixes

FornaxA <fornaxa@servitising.org> (111):
- `b299cf62` Introduce wrappers for Coin and AccessCoin()
- `769efded` Update EncodeDestination(), DecodeDestination() and IsValidDestination()
- `ec312472` Use unique_ptr for zerocoinDB/pSporkDB
- `30d68852` Resolve merge issue
- `8caa1c29` Update script_tests.cpp and src/Makefile.am in preparation of enabling --with-libs
- `fa790dd7` Separate libbitcoinconsensus from libbitcoin_consensus
- `c323d814` Update makefiles to make available common functionality to wallet sections
- `cb6b897b` Add variable for max ops in a script
- `457352ad` Temporarily disable tests and unfinished ports
- `3cf476f5` Refactor: test_bitcoin.h renamed to test_ion.h
- `45f8aaf4` Enable group tx checks that use AccessCoin() wrappers
- `b618ae86` Update code formatting
- `b24ce270` Update SignTransaction()
- `5b936bf6` Remove anti fee sniping code from tokengroupwallet
- `913ba9f0` Add twice the size of an input to the tx size for fee estimation
- `00da6625` When token desc parameters are given:
- `4ce51b3d` Do not include authority utxo's when counting all group balances
- `33a5e60d` Add and update Token Group helper functions
- `14c8b03d` Add Group Token Management functions
- `4c74ae34` Add tracking and storing of XDM amount for fee calculation
- `29145d7e` Add token log messages to ION logging group
- `f16f2a49` Remove duplicate data from CTokenGroupInfo by wrapping quantity to provide controllingGroupFlags
- `edcd9300` Add serializer methods to CTokenGroupInfo and CTokenGroupID
- `e5866898` Add comparison functions to CTokenGroupID
- `f2f9ad2c` Add scantokens RPC command
- `1094482b` Managing token overview; unfinished 1st commit.
- `cc79f9bb` Token description - unfinished
- `729bd6c4` Use shared_ptr for CTokenGroupManager
- `91d2c5cf` Logging cleanup
- `65e97e55` Token description - second commit
- `f4b3cc8b` Add token database
- `27d5f1e4` RPC - update function to display token group descriptions
- `04bd7511` Fix block header version issue
- `18d8829d` Token group manager: clear token list on reindex
- `2d5300bf` Match and store management tokens in a map
- `fe061707` Count and track Dark Matter transactions
- `dc558a9f` Fix merge issue - count and track xdm
- `201833b5` RPC command for querying dark matter transaction count info
- `f2e1b5a1` Ensure token group ticker and string are unique
- `84d27f74` Add field for token amount (floating) decimal position
- `ccd00f75` Refactor: separate validation from writing to memory when adding token groups
- `bef94c06` Refactor: move gBalance and GROUPED_SATOSHI_AMT to include file
- `de62fed3` Add management token helper functions
- `73058ed1` Apply the DarkMatter fee structure
- `cb80cced` Update RPC functions to add DarkMatter fees to transactions that need it
- `2180628f` Correct DarkMatter transaction fee calculation
- `31a23084` Improve token description validation and filtering
- `c5b9d914` Update testnet accumulator checkpoints
- `cab741fb` Update PoW functionality for mining on regtest
- `f44f1138` Update testnet token management key
- `964965ce` Improve token decimalPos and token amount handling
- `70ee4a05` Improve handling and filtering of token descriptions
- `ad60a42d` Update managementtoken RPC command parsing
- `f84662ed` Increase default maximum size for OP_RETURN relaying
- `053558ec` Do not allow regular tokens before creation of Management Tokens
- `d9f4325f` Add 'token checknew' command
- `f1cda72d` Move TransactionRecord from qt to wallet section
- `ff3943c1` Add authorities to 'token balance'
- `237bef3d` Update test for grouped outputs
- `c59b96a1` Finish functionality for listing and dropping authorities
- `6fea43cf` Allow Management Token transactions before regular token phase
- `e0c4d66e` Ensure grouped coins are not staked
- `aefd1798` No XDM fees for melting XDM tokens
- `3a42e42e` Update find grouped authorities to be case insensitive
- `59886b88` Add tokeninfo by ticker, name or groupID
- `d0a16a86` Remove sticky_melt bit from management token creation parameters
- `dd74d92d` Limit wallet unlock check to active token operations
- `0927f688` Additional checks to avoid accepting token group transactions
- `65d54283` New token start height for testnet
- `947edf12` Reset management token pointers when removing their groups
- `4d8aae62` Update variable names for removing token groups to better reflect their function
- `23fcf10e` Add helper function for identifying token group inputs
- `255d9c43` Add helper function for identifying management token inputs
- `f9b93593` Create helper functions for testing if management tokens have been created
- `c9835756` Use Magic Token for management functions instead of using the Token Management Key
- `05bdeac4` Track, database and display management token statistics
- `6cd6a234` Exclude grouped inputs by default from AvailableCoins()
- `a8e84b97` Set token regtest parameters
- `b2565455` Rename token helper functions
- `ce096716` Add token helper functions
- `19ed2892` Require token authorities to mature before using them
- `cf3f93c8` Update spork count
- `359bd888` Add name and ticker to token balance output
- `5dec8c23` Update token description validation related code
- `12db2d9a` Update formatting of token values in RPC commands
- `ee75f098` Update token database re-initialization
- `3d7594f0` Replace past softfork checks with their block height counterparts
- `24826b3b` Update token start height and set block version check
- `322d51fa` Update testnet checkpoint and fork testnet
- `cc66622c` Add protocol number bump and prepare corresponding spork
- `d7cb7dec` Change sync parameters
- `bac0f4e2` Move token files into tokens subdir
- `f16491ca` Separate token rpc functionality from token wallet functionality
- `f5b3502d` Various clean-ups
- `55350f43` Increase OP_RETURN data size to allow for longer URL's in the token description data
- `e2c0f54b` Replace the RPC command 'token' with more specific commands
- `2f8cf107` Add -reindextokens help output and update man pages
- `02400929` Take a subgroup's creation tx from the parent
- `9413fc61` Correct for token amount calculation edge case decimalPos=16
- `92ce3ee2` Update configuretoken help command to show that all parameters are required
- `9ede2c2d` Add helper functions for token distribution
- `72ee2742` Add WriteLE16 and ReadLE16
- `2f3280a0` Add the (reserved) configure token flag.
- `3796d4da` Improve output and help descriptions
- `eea1a2ed` Revert inflated zerocoin calculation update
- `3e45d63d` Remove tracking Magic token transactions in the block index
- `127bc602` Set the block heights for token start and zerocoin public spend start
- `1ea31de7` FilterCoins should not return immature stakes
- `0afcbc83` Add pre-DGW customization
- `0924111b` Link new stake modifier to block version 11
- `3c1e97f7` Update chain parameters

G. Andrew Stone <g.andrew.stone@gmail.com> (2):
- `bed644fb` add token-only listsinceblock and listtransactions functionality
- `a793a6f0` fix minimal_data encodings for group data by disallowing 1 byte group data, although allowing 1 byte encodings are committed in this PR as comments for posterity. At the same time, fix other issues with Script APIs and minimal_data encodings, even though group isn't using them

Jonas Schnelli <dev@jonasschnelli.ch> (5):
- `6d979ab6` Add FindScriptPubKey() to search the UTXO set
- `e391b6c7` Blockchain/RPC: Add scantxoutset method to scan UTXO set
- `e7e85fee` scantxoutset: add support for scripts
- `d9741bfb` scantxoutset: support legacy P2PK script type
- `065bd46f` scantxoutset: mention that scanning by address will miss P2PK txouts

MarcoFalke <falke.marco@gmail.com> (1):
- `4cb364fa` Properly display required fee instead of minTxFee

Mitchell Cash <mitchell@mitchellcash.com> (3):
- `aab17f1d` Bump build version to 4.0.0
- `9ba4d842` Correct remote URLs in gitian build configs
- `e5365349` Update manpages for 4.0.0

Pieter Wuille <pieter.wuille@gmail.com> (2):
- `e334e6ff` Introduce Coin, a single unspent output
- `ab58695b` Encapsulate CLevelDB iterators cleanly

Russell Yanofsky <russ@yanofsky.org> (1):
- `720f523d` Don't return stale data from CCoinsViewCache::Cursor()

Wladimir J. van der Laan <laanwj@gmail.com> (2):
- `5452e1cb` Add debug message to CValidationState for optional extra information
- `63a4e993` txdb: Add Cursor() method to CCoinsView to iterate over UTXO set

cevap <dev@i2pmail.org> (143):
- `2ac049f7` snap: update snapcraft, fix amd64, i386 builds, update ignore and docs
- `b7de5867` Fix yaml
- `10ec1f6d` Bump version to master and mark release as false
- `a005a186` Fix arm/aarch64 builds downloads and bump to master
- `09c3809a` Add ion developers copyright info to the snapcraft.yaml config
- `36a674a8` Update checkpoint after zerocoin v2 startheight, add accumulator checkpoint
- `031dec6c` Update hardcoded seeds from chainz
- `eaf7db07` Update README.md with v3.1.02
- `13cebbf5` Bump version to v3.1.02 and set release as true
- `3a4ae942` Update testnet checkpoint, add accumulator checkpoint
- `1645dfdf` update accumulator checkpoints, update chainparams
- `c948517d` Revert accumulator checkpoints as all are released now
- `79ad40cb` --------------------------
- `75dcbe72` fix merge errors
- `59504b59` snap - remove double source-tag
- `2bc20fe9` snap - fix name
- `fa4fa645` snap - update snapcraft.yaml, use core18 base, minor  fixes
- `d1964c40` snap - add patch to use snap instead of dirty
- `66fa7575` snap - remove old snap/guifolder
- `f7cf0871` snap - retrigger snap builds for release version v3.1.02
- `8cedba79` snap - remove desktop-launch, add environment variable, update plugs, retriggers build
- `dbe6d6bd` snap - retrigger snap building from master, (edge, beta channels
- `5bc2a726` update README.md, change cevap refs to ioncoincore
- `4d5cba96` build - fix preparebudget
- `92987019` snap - update snapcraft.yaml's ref to MIT license
- `c4a8001c` transifex - update transifex info
- `695c7565` build - debian, update control file
- `29722baa` build - debian, update changelog
- `50a09baa` build - debian, add build.sh for local testing
- `e04c96a1` build - debian, delete contrib/debian folder
- `8bd0edf8` build - debian, create debian control file and other debian relalted files
- `0e1a5590` docs - change contrib/debian refs to debian
- `298739f0` docs - update contrib/README.md, replace bitcoin with ion
- `3eb4a176` build - debian, update man pages
- `2fa15833` tests - disable checkzerocoinmint_test and fix wrong accumulator
- `2f1e2e5d` tools and scripts - build-dpkg.sh, comment out a command moving debian folder
- `1965b714` build - debian, add event and zmq3 to dependencies
- `a86214bb` build - debian, remove qtwayland5
- `d5f86113` build - fix build warning about syntax specified for the proto file
- `d2d04db4` build - fix Warning: The name 'label' (QLabel)
- `dcc6351a` build - fix Warning: The name 'verticalLayout' (QVBoxLayout)
- `ec475103` [build][tests] - fix failing dpkg build due to failed tests **TODO**
- `81642d86` build - debian, use libzmq3-dev and libevent-dev to fix dpkg warning
- `4a6b567d` lint - fix white space in build-dpkg.sh and remove last line
- `1d0ea854` tests - set correct block height for used accumulator checkpoint
- `bb804adb` tests - trasaction tests, update tx for basic tests, ref 9b5a0306ced7ce352cb53f5f0c279be5a91538d1
- `ff1971c8` tests - fix all tests to pass and unmark those which are not passing **TODO**
- `351d4903` travis - disable temp lint whitespace for test data
- `b2e52a3e` snap - update description
- `dee0704d` tools and scripts - add debian scripts
- `f2372ebf` build - update manual pages
- `a9a404b7` tests - uncomment unused variable
- `f71a89cd` tests - mark out unused vars
- `d36832c0` leveldb - fix ecx warning that it is not initialized, intilize it with 0
- `f828c23c` build - configure, mark out bitcoin-util-test.py
- `8375f550` travis - enable RUN_UNIT_TESTS
- `42019e6c` leveldb - fix missing binary operator before token
- `fe1f1009` build - fix commenting at start of a rule is unportable, delete it
- `d096241c` build - debian replace libdb4.8-dev with libdb4.8-dev
- `b84e33fb` build - db4.8, use imported binaries from bitcoin
- `b2102c1a` build - db4.8, use update control
- `907707a1` tools and scripts - remove temp added folders/files in lint-whitespace.sh
- `318b8fe5` build - db4.8, use update dependencies
- `63f46d37` build - db4.8, use debian, add ion-tx to the control file
- `ce67af0a` build - debian control, add locales-all packaged
- `55cb174e` build - debian control, add  bash-completion
- `ac482f14` doc - update readme.md
- `d5d69d65` doc - move snaps README.me to snap/README.md
- `08f6297f` build - fix failed qt test by commenting it out, required for deb building on launchpad
- `6fca2caf` build - set snap grade to devel and mark as non release
- `2d6ad785` build - debian, add ion-cli manual pages
- `3bc47560` build - debian, add ion-qt manual pages
- `77207685` build - debian, update descriptions in control file
- `bd4582ae` build - debian, update copyright
- `f37ac7b1` build - snap, move everything to share/snap folder
- `0b103311` build - debian, add testnet and regtest icons, protocols, shortscuts and manpages, update qt install
- `cb3e44c5` GUI - optimize images
- `519beb57` cleanup, remove accidentially added tmp files
- `2fbc86c4` build - snap, add test_ion and test_ion-qt
- `ff4e2840` build - snap, add test_ion and test_ion-qt, change command
- `3c763695` build - create daemon icon
- `2b121eb1` build - add additional packages to deb build
- `181cb345` travis - add temporarly debian/control to the whitelist
- `59754119` build - snap, update icons and shortcut fixes
- `0debfd2a` build - optimize iond share images
- `7556cf35` gui - change browse, save file and icon when there is not connection
- `92eafce7` gui - debian, add iond share xpms
- `7617378c` script and tools - add info and copyright to build-dpkg.sh
- `54dd63e0` update .gitignore, add .debbuilder, config.guess and config.sub
- `6ed7ae66` update .gitignore, add debian tmp build files
- `e33ac18f` cleanup, delete .vscode/settings.json
- `d166af09` build - travis, add temporarly build-dpkg.sh to the whitelist
- `072e274f` doc - update release notes
- `d03144fb` build - debian, update compatibility levels from deprecate 7 to 10
- `267766b8` build - debian, fix not finding ioncoin.conf.5
- `92f5e186` scripts and tools - update build-dpkg, remove tmp dir
- `49908f97` build - debian, fix error due to compatibility upgrade
- `132a87c1` scripts and tools - fix typo
- `8108b858` snap - remove patches part
- `87f3ae08` build - snap, remove desktop part
- `8eb88d3b` build - snap, create shar/applications folder and create iond desktop icon
- `4f9030bb` build - debian, update control descriptions
- `b870a860` build - snap, delete non required icons
- `cba6342e` build - snap, add copy and patching of shortcuts copied from debian
- `230314f1` build - snap and debian, update manpages
- `2fe675a2` build - snap and debian, update icons to reflect --version info
- `0fa1e822` build - snap, delete junk code
- `85250f66` build - snap, fix wrong extension, retrigger build
- `3e1c0b9b` build - snap, remove unrequired vars
- `e36c1361` build - snap, use iond.ico for all launchers, testnet, regtest and main, after artwork is added, we will change regtest and testnet daemon icons
- `6b264c6a` build - snap, patch iond shortcuts and copy them
- `cbea092e` build - snap, fix missing icon caused by wrong var usage
- `ef642fb3` build - snap, remove else part of .desktop copying
- `11de2177` build - snap, shorten urls in description and use a loop for patches
- `01d57727` build - snap, use filename without suffix
- `7a7f74b2` build - snap create data folder and copy example config
- `81f61222` build - snap, delete .patch suffix in files and update snapcraft.yaml
- `883f3858` build - snap, reset PATCH var in a loop
- `1bb18162` build - snap, revert git single instead of a loop
- `07806c42` build - snap, remove if do done, replace with static routines for each file
- `958ba78f` build - snap, find in prime dir instead current
- `8666b4ec` build - snap, replace static value with vars and start test
- `fe9606cf` build - debian control, replace long urls with tinyurl
- `9035140e` build - snap, fix building error
- `8708373f` remove debian/control from lint-whitespace.sh
- `d7e943ff` build - snap, fix building for ppc64el
- `fe594b4a` doc - start preparing release notes for v3.2.0
- `31e8711e` snap - fix typto in filenape favicon_regtest.ico
- `ccd528a7` fix merge
- `0dedfb90` snap - add ion main logo icon png
- `b1b46132` snap - add missing icon
- `e37691a5` artworks - create repository graph source
- `8b2831c6` snap - add missing daemon snap icon
- `a2808d55` scripts and tools - resort vscode debugerr config
- `1f2adda1` scripts and tools - update launch.json with new entries
- `82e14f56` scripts and tools - fix ppc64el failing due to non existing test bins
- `9a58d732` gui - update sendcoinsdialog
- `1bb7accf` fix wrong brackets in accumulator checkpoints
- `156a7d8d` doxygen - update icon and add to SVG source
- `e27b1851` build - debian, fix not met build-depends
- `0b42987d` snapcraft config, use BINPREF instead of hardcoded name
- `6038948d` gui - change spinner to ion logo
- `67b399e9` gitian: remove non stable architectures from building

ckti <ckti@3re.io> (11):
- `7deabf92` Increase font size of xION status messages
- `4f412a9b` Change error message when selecting more than 5 xION imputs
- `c0f676cb` Change getxionseed help message - Issue #124
- `89d62ed1` Fixes for Checkpoints and key tests
- `f471799d` Remove whitespaces
- `7f68c05e` Update keytest  -- add in working tests
- `bdd22355` Update key_tests
- `643d7e4c` Use cases as documented at https://github.com/ionomy/ion/wiki/
- `7b59eb48` CLI & Masternodes tests
- `1ef9f1a8` Add in working test_runner and update test_framework
- `339f5746` New tests for token use cases

furszy <5377650+furszy@users.noreply.github.com> (2):
- `e15482a1` AcceptBlock() check for double spent serials only on main chain flag.
- `2ee5bc8a` AcceptBlock() check for double spent serials only on main chain flag.

ioncoincore <ioncoincore@gmail.com> (2):
- `25a36d26` Fix testnet accumulator
- `c5fd8417` Some cleanup: - Increase max ticker length to 10 - Decrease max name length to 30 - Remove unneeded texts

jtimon <jtimon@jtimon.cc> (1):
- `2ab7bcf2` Consensus: MOVEONLY: Move CValidationState from main consensus/validation

kwwood <35408547+kwwood@users.noreply.github.com> (1):
- `13d51c05` Update README.md

practicalswift <practicalswift@users.noreply.github.com> (1):
- `2501b798` Use unique_ptr for pcoinscatcher/pcoinsdbview/pcoinsTip/pblocktree

random-zebra <random.zebra@protonmail.com> (5):
- `6df4ab0b` AcceptBlock: contextual zcspend check on main chain
- `06137758` remove extra debug lines in AcceptBlock
- `de08e1d5` AcceptBlock: contextual zcspend check on main chain
- `8b923b4d` remove extra debug lines in AcceptBlock
- `6469ebc5` Upstream upgrades: new stake modifier
