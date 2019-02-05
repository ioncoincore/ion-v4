// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The Ion developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Params.h"
#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
        (       0,	uint256("0000004cf5ffbf2e31a9aa07c86298efb01a30b8911b80af7473d1114715084b") ) // Genesis block
        (    1000,  uint256("0000000144b22b0af9bced65256d5eccc4e3f112a89bdb0f08ab8dc2a6145b56") ) // Last PoW block
        (    1001,  uint256("a66b31f9841cc86f85a89142641b4c02f43065dda1818002595d2cef6b0b7cc2") ) // First PoS startheight block
        (  100000,  uint256("a5a4e8f2554cda59955e0117fd71245e1f6d73a30ab420a3d3731384dcbcfffc") )
        (  200000,  uint256("e6f984e3fe6bf992d640f30ad3c28777b303b4b3b59bd7bf3f696566abe08c13") )
        (  300000,  uint256("d6b6250ec6bedf74663a10babf5774562736fa99f7dd0a53841a4c95b1b8ec11") )
        (  400000,  uint256("507851828598daf03711e6eaed1709f17837a105dd62209ff68d2cf1dc6ddf7a") )
        (  550001,  uint256("aa063547717c4e9f1f1593a580143491896cde85a0b369442d629cd364a1b78d") ) // Zerocoin Start (v8)            1521903907   1464462
        (  550142,  uint256("4a9e4ee53bc441e0aadf788b5daa9b8d01a3a6debed01b5c599d6f7e22f4f7d0") ) //                                1521912217   1464746
        (  552317,  uint256("654cf4e6d0e9d8249075c674a54859849b2648cfe35ea71e25bd6394f24331b2") ) // Last block                     1522095098   1469475
        (  853104,  uint256("9623e2c68f6eab9f91ac9ca4b65a2049a05f223f970ca2d3cf8280ad1ead5efc") ) // v3.1.0                         1540360964   2232434
        (  860817,  uint256("b78531efc5d878f8afc5aa9fd349d0181e8cc213853251aad63839d59781a716") ) //                                1540827763   2251929
        (  886654,  uint256("c816d0e907ab44f43ec6bef321ac2c9b4e4a578c9ee4e7946e4a74c3073edf66") ) //                                1542390128   2316854
        (  908698,  uint256("aa44b1eebd7ad5d4bc7b428dcdacd527677fa639557b58666a68dc2fdba3f133") ) // Last active zerocoin v1 block  1543722397   2371470 (zerocoin v1 disabled: 1543722400)
        (  936756,  uint256("873aa1d52ca79dc77d67f8162a2a60b9c936f50449b58b5464b91e412d351c29") ) //                                1543729708   2371718
        (  956579,  uint256("bac382323420c9c8e89024b66a3cab28d6133ca7450eae07de63364f74f087f6") ) //                                1546631813   2492172
        (  980729,  uint256("a12927283f8396a65bf45cf516f5d8a2c618ac6b2a9cc530cdd962c9263b3398") ) //                                1548101941   2552465
        (  997048,  uint256("5fcdcf658a5b20a8c8e2c583a68122e9c0b66804f6c2941384c53cf90490d210") );//                                1549093695   2592520
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1548101941, // * UNIX timestamp of last checkpoint block
    2592520,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    3490        // * estimated number of transactions per day after checkp
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
	(       1,      uint256("000000b86fdd7f2ae9e9973e73790492989113075a2d5c581495ab7bb2ad5711") ) // First block 
	(      10,      uint256("0000008c29a7d680710d1cc821d79f33ba0159bc26d9e233bccfabd668b0430e") ) // Confirmation of first block
	(      73,      uint256("0000000000414be74794bb2e455e24c0e446ad36df162c69a81742dc07f51d0d") ) // 
	(      74,      uint256("1881b795f7531232ba90ade14c16b7f0cf9392b6c9fe76a3d5bfeab9150b7dca") ) // ERROR: AcceptBlock : prev block 1881b795f7531232ba90ade14c16b7f0cf9392b6c9fe76a3d5bfeab9150b7dca is invalid, unable to add block c54904618b734eeb3f098b442934586806f869e80656eacfba65ca91a091cf31
	(      75,      uint256("c54904618b734eeb3f098b442934586806f869e80656eacfba65ca91a091cf31") ) // ERROR: AcceptBlock : prev block 1881b795f7531232ba90ade14c16b7f0cf9392b6c9fe76a3d5bfeab9150b7dca is invalid, unable to add block c54904618b734eeb3f098b442934586806f869e80656eacfba65ca91a091cf31
	(     300,      uint256("000000125e3e3d005aa72281e02b4ebaabc2fa9aed817b9365a8d29bb7901c10") ) // Last POW Block
	(   75000,      uint256("20faec3994dac57fb88748e29139974522c91036e1bf8ff204c769a90fab5a12") ) // Fork June 2017
	(   85000,      uint256("43ee28cd1f804dafe05ef120569726e50e9e6f2b634746925742cbd9f738c201") ) // Fork June 2017
	(   88800,      uint256("2807b46cbfa28a2d4854215b40f4db64b62fc71a1d010844d67d7c03888ce692") ) // Fork June 2017
	(  331099,      uint256("1ba565ae5336eeb1cbdc4c8804f229f685391d6b9a8568f7baf5c70b80bed17e") ) // Testnet Fork June 2018
	(  331100,      uint256("ffa0eaa61e9b2291dd497338235d071b0e9eb71d4fda723ce778f52b38e349fe") ) // Testnet Fork June 2018
	(  443601,      uint256("c5e9467f24b1d149a9716776be2fdc806af2db54d11330df33bb931f8ebf6254") ) // Testnet Fork June 2018
	(  472999,      uint256("5d55f229074b930f4dd42a0f4e0e2f1d855dcd1d87cb86553ea21c797825482c") ) // Testnet Fork June 2018
	(  473000,      uint256("237bc8d1e7cb02af8cd3e6affe1fa134c1a29a4852f3fa177ebcd50014463152") ) // Testnet Fork December 2018; timestamp=1545338100  txcount=947151
    (  500535,      uint256("d6a5202217fcbdbe34592e78038937cb89541cb41051492bde6d061188285086") ) // timestamp=1547025824 txcount=1003348
    (  516559,      uint256("8b91cc91179419e72777e51b3c298fd29df8827256b361c48cf61bab0b1e1bb5") ) // timestamp=1548102045 txcount=1035503
    (  532875,      uint256("483a77879f686a3e04076776ef82409ff17c4955d04c5b221ace7bfd4c3b5086") );// timestamp=1549094295 txcount=1070146
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1549094295,
    1070146,
    3017};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};

libzerocoin::ZerocoinParams* CChainParams::Zerocoin_Params(bool useModulusV1) const
{
    assert(this);
    static CBigNum bnHexModulus = 0;
    if (!bnHexModulus)
        bnHexModulus.SetHex(zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParamsHex = libzerocoin::ZerocoinParams(bnHexModulus);
    static CBigNum bnDecModulus = 0;
    if (!bnDecModulus)
        bnDecModulus.SetDec(zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParamsDec = libzerocoin::ZerocoinParams(bnDecModulus);

    if (useModulusV1)
        return &ZCParamsHex;

    return &ZCParamsDec;
}

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xc4;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xd8;
        pchMessageStart[3] = 0xec;
        vAlertPubKey = ParseHex("04ab1a302b40c65c08281974e4ccbe6df987d8a87cbc490ace9a261d8a57b809a5dad39f53bdc85e392c61c3c5a3f990d53430bb40a731ff28fa2255fecef70da3");
        nDefaultPort = 12700;
        bnProofOfWorkLimit  = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        bnProofOfStakeLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        nSubsidyHalvingInterval = 210000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 8100; // 75%
        nRejectBlockOutdatedMajority = 10260; // 95%
        nToCheckBlockUpgradeMajority = 10800; // Approximate expected amount of blocks in 7 days (1440*7.5)
        nMinerThreads = 0;
        nTargetTimespanMidas = 7 * 24 * 60 * 60;    // 1 week
        nTargetTimespanDGW = 1 * 60; // ION: 1 day
        nTargetSpacing = 1 * 60;  // ION: 1 minute
        nMaturity = 60;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 38600000 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 1000;
        nModifierUpdateBlock = 615800;
        nZerocoinStartHeight = 550001;
        nZerocoinStartTime = 1521851265;            // GMT: Saturday, March 24, 2018 12:27:45 AM,
        nBlockEnforceSerialRange = 550137;          //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 550137;     //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 99999999;           //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 550137;          //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 550137;          //Start enforcing the invalid UTXO's
        nInvalidAmountFiltered = 0*COIN;            //Amount of invalid coins filtered through exchanges, that should be considered valid
        nBlockZerocoinV2 = 1012710;                 //!> The block that zerocoin v2 becomes active - roughly GMT: Thursday, February 7, 2019 12:00:01 AM
        nEnforceNewSporkKey = 1548979201;           //!> Sporks signed after, GMT: Friday, February 1, 2019 12:00:01 AM must use the new spork key
        nRejectOldSporkKey = 1549497601;            //!> Reject old spork key afters, GMT: Thursday, February 7, 2019 12:00:01 AM

        nMidasStartHeight = 176500;                 // MIDAS startheight, first big attack
        nMidasStartTime = 1497541280;               // Time when MIDAS started and old algorithm stopped
        nDGWStartHeight = 550000;                   // Startheight of DGW
        nDGWStartTime = 1521851265;                 // GMT: Saturday, March 24, 2018 12:27:45 AM - Exact time when DGW algorithm starts and old MIDAS stops

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = "The Guardian: [2nd Feb 2017] Finsbury Park mosque wins apology and damages from Thomson Reuters";
        genesis.nTime = 1486045800; // GMT: Thursday, February 2, 2017 14:30:00
        CMutableTransaction txNew;
        txNew.nTime = genesis.nTime;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 1486045800 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("045622582bdfad9366cdff9652d35a562af17ea4e3462d32cd988b32919ba2ff4bc806485be5228185ad3f75445039b6e744819c4a63304277ca8d20c99a6acec8") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nBits = 0x1e00ffff;
        genesis.nNonce = 28884498;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000004cf5ffbf2e31a9aa07c86298efb01a30b8911b80af7473d1114715084b"));
        assert(genesis.hashMerkleRoot == uint256("0x7af2e961c5262cb0411edcb7414ab7178133fc06257ceb47d349e4e5e35e2d40"));

        vSeeds.push_back(CDNSSeedData("1", "main.seeder.baseserv.com")); // Ionomy official seed 1
        vSeeds.push_back(CDNSSeedData("2", "main.seeder.uksafedns.net")); // Ionomy official seed 2

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 103);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 88);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x73)(0x79)(0x78).convert_to_container<std::vector<unsigned char> >();

        bech32_hrp = "ion";

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "04e892d181f083856991c4e68f82b935dad9ca5dee2fb912ceb0247c3670725f879bfdb718be019f7a0bc53f77105f60a8ed750b16e55c220b4b6c47279d7dce17";
        strSporkKeyOld = "04f8c457bd279e667228d38faf2032958ee80ead5ec3d04ab92eeab54ac078ea2a79a2a03dee10634123cc47ea795699bd02b6370e040b622b2f15bcc56dafc2b7";
        strObfuscationPoolDummyAddress = "ijeSPVizJAFuKx4E3rEAcadQR5tZF9cjC8";
        nStartMasternodePayments = 1558696182; // GMT: Thursday, 15. February 2018 12:03:02

        /** Zerocoin */
        zerocoinModulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
            "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
            "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
            "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
            "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
            "31438167899885040445364023527381951378636564391212010397122822120720357";
        nMaxZerocoinSpendsPerTransaction = 7; // Assume about 20kb each
        nMinZerocoinMintFee = 1 * CENT; //high fee required for zerocoin mints
        nMintRequiredConfirmations = 20; //the maximum amount of confirmations until accumulated in 19
        nRequiredAccumulation = 1;
        nDefaultSecurityLevel = 100; //full security level for accumulators
        nZerocoinHeaderVersion = 8; //Block headers must be this version once zerocoin is active
        nZerocoinRequiredStakeDepth = 200; //The required confirmations for a xion to be stakable

        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xdb;
        pchMessageStart[1] = 0x86;
        pchMessageStart[2] = 0xfc;
        pchMessageStart[3] = 0x69;
        vAlertPubKey = ParseHex("0432f3e3c6c8ce236579b3223debc2b684f0ffa14fd3fe6813eafe3f3dd3b45664d1efbdfe43441edc83d1c4507ab9bd395c8134797e04457965031a4b6413bb1a");
        nDefaultPort = 27170;
        nEnforceBlockUpgradeMajority = 4320; // 75%
        nRejectBlockOutdatedMajority = 5472; // 95%
        nToCheckBlockUpgradeMajority = 5760; // 4 days
        nMinerThreads = 0;
        nTargetTimespanMidas = 7 * 24 * 60 * 60;   // 1 week
        nTargetTimespanDGW = 1 * 60; // ion: 1 day
        nTargetSpacing = 1 * 60;  // ION: 1 minute
        nLastPOWBlock = 300;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 51197; //approx Mon, 17 Apr 2017 04:00:00 GMT
        nMaxMoneyOut = 38600000 * COIN;
        nZerocoinStartHeight = 331100;
        nZerocoinStartTime = 1521414629;
        nBlockEnforceSerialRange = 10000000; //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 10000000; //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 99999999; //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 10000000; //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 10000000; //Start enforcing the invalid UTXO's
        nInvalidAmountFiltered = 0; //Amount of invalid coins filtered through exchanges, that should be considered valid
        nBlockZerocoinV2 = 474100; //!> The block that zerocoin v2 becomes active
        nEnforceNewSporkKey = 1545361200; //!> Sporks signed after 12/21/2018 @ 3:00am (UTC) must use the new spork key
        nRejectOldSporkKey = 1545620400; //!> Reject old spork key after 12/24/2018 @ 3:00am (UTC)

        nMidasStartHeight = 75000;
        nMidasStartTime = 1497209344;
        nDGWStartHeight = nZerocoinStartHeight;
        nDGWStartTime = nZerocoinStartTime;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        const char* pszTimestamp = "The Guardian: [2nd Feb 2017] Finsbury Park mosque wins apology and damages from Thomson Reuters";
        genesis.nTime = 1491737471; // GMT: Thursday, February 2, 2017 14:30:00
        genesis.vtx.clear();
        CMutableTransaction txNew;
        txNew.nTime = genesis.nTime;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 1491737471 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("045622582bdfad9366cdff9652d35a562af17ea4e3462d32cd988b32919ba2ff4bc806485be5228185ad3f75445039b6e744819c4a63304277ca8d20c99a6acec8") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);

        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nNonce = 1603027;
        genesis.nBits = 0x1e00ffff;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000002bed128b6b2a62bd8edd4e6f8a414eac38e256aa0194adb8c93fe18132"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1", "testnet.seeder.baseserv.com"));
        vSeeds.push_back(CDNSSeedData("2", "testnet.seeder.uksafedns.net")); // Ionomy official testseed 2"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 97); // Testnet ion addresses start with 'g'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);  // Testnet ion script addresses start with '2'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239); 
        // Testnet ion BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xcf).convert_to_container<std::vector<unsigned char> >();
        // Testnet ion BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x91).convert_to_container<std::vector<unsigned char> >();
        // Testnet ion BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        bech32_hrp = "tion";

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "0430b1f83d3acb90cde0b7e0e1d9365c00bfaf04ab8614457cfa0766a787239dd47ad6ca478659dd5e401fccb7fea6fa83acad23a2c7b451aafe6fa2ae4cfd4a58";
        strSporkKeyOld = "0470e14fc60a25e0eb4f6b1fe280e4c3f9427f7bb8b38f14a0c310c2e56402bdce0f25049bf22351dc3d07f389d4d433b339d8e1b991784f11df68f50340185c1d";
        strObfuscationPoolDummyAddress = "gED9bYvicBsQ5Gu2zeaK8iZgrPqkLXYhgc";
        nStartMasternodePayments = 1558696183; // GMT: Thursday, 15. February 2018 12:03:03
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xb5;
        pchMessageStart[1] = 0x9a;
        pchMessageStart[2] = 0x39;
        pchMessageStart[3] = 0x9e;
        vAlertPubKey = ParseHex("04fd1e6ac50fc8102fabf2926011f86c7f4e2933877a70b0cf945f32588b010832f09239f572785f24e8bd6c14b4f7fb5a1987ac908780ac17d0eb9fea242fa883");
        nDefaultPort = 34567;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 4320; // 75%
        nRejectBlockOutdatedMajority = 5472; // 95%
        nToCheckBlockUpgradeMajority = 5760; // 4 days
        nMinerThreads = 1;
        nTargetTimespanMidas = 7 * 24 * 60 * 60;    // 1 week
        nTargetTimespanDGW = 24 * 60 * 60;          // ION: 1 day
        nTargetSpacing = 1 * 60;                    // ION: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nLastPOWBlock = 100;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 1; //approx Mon, 17 Apr 2017 04:00:00 GMT
        nMaxMoneyOut = 38600000 * COIN;
        nZerocoinStartHeight = 20;
        nZerocoinStartTime = 1521414629;
        nBlockEnforceSerialRange = 10000000; //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 10000000; //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 99999999; //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 10000000; //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 10000000; //Start enforcing the invalid UTXO's
        nInvalidAmountFiltered = 0; //Amount of invalid coins filtered through exchanges, that should be considered valid
        nBlockZerocoinV2 = 120; //!> The block that zerocoin v2 becomes active
        nEnforceNewSporkKey = 1545361200; //!> Sporks signed after 12/21/2018 @ 3:00am (UTC) must use the new spork key
        nRejectOldSporkKey = 1545620400; //!> Reject old spork key after 12/24/2018 @ 3:00am (UTC)

        nMidasStartHeight = 99999999;
        nMidasStartTime = 9997209344;
        nDGWStartHeight = nZerocoinStartHeight;
        nDGWStartTime = nZerocoinStartTime;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        const char* pszTimestamp = "The Guardian: [2nd Feb 2017] Finsbury Park mosque wins apology and damages from Thomson Reuters";
        genesis.nTime = 1491737471;                 // GMT: Thursday, February 2, 2017 14:30:00
        genesis.vtx.clear();
        CMutableTransaction txNew;
        txNew.nTime = genesis.nTime;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 1491737471 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("045622582bdfad9366cdff9652d35a562af17ea4e3462d32cd988b32919ba2ff4bc806485be5228185ad3f75445039b6e744819c4a63304277ca8d20c99a6acec8") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);

        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nNonce = 574752;                  // hex 57 47 52 in text = ION
        genesis.nBits = 0x207ffff;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 34567;
        assert(hashGenesisBlock == uint256("0x47c7c6267ccd4a73c21c696d4bc004f74edc172a470c9c5a4201aa8d3196f99e"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 2;
        strSporkKey = "04fd1e6ac50fc8102fabf2926011f86c7f4e2933877a70b0cf945f32588b010832f09239f572785f24e8bd6c14b4f7fb5a1987ac908780ac17d0eb9fea242fa883";
        strSporkKeyOld = "0470e14fc60a25e0eb4f6b1fe280e4c3f9427f7bb8b38f14a0c310c2e56402bdce0f25049bf22351dc3d07f389d4d433b339d8e1b991784f11df68f50340185c1d";
        strObfuscationPoolDummyAddress = "g9gvvemz52aDkRn4iiGrzTbBRS1HiqcY9r";
        nStartMasternodePayments = 1558696183; // GMT: Thursday, 15. February 2018 12:03:03
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
        bech32_hrp = "ionrt";

    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 27770;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        bech32_hrp = "ionut";
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
