// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include "test/test_ion.h"
#include "consensus/tokengroups.h"
#include "main.h"
#include "miner.h"
//#include "parallel.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tokengroup_tests, BasicTestingSetup)

CAmount authorityFlags(GroupAuthorityFlags f, uint64_t amt = 0)
{
    amt &= ~((uint64_t)GroupAuthorityFlags::ALL_BITS);
    return (CAmount)(((uint64_t)f) | amt);
}

// create a group pay to public key hash script
CScript gp2pkh(const CTokenGroupID &group, const CKeyID &dest, CAmount amt)
{
    CScript script = CScript() << group.bytes() << SerializeAmount(amt) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                               << OP_HASH160 << ToByteVector(dest) << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}

std::vector<unsigned char> breakable_SerializeAmount(CAmount amt)
{
    uint64_t num = (uint64_t)amt;
    CDataStream strm(SER_NETWORK, CLIENT_VERSION);
    if (num < 256)
    {
        ser_writedata8(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata16(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata32(strm, num);
    }
    else
    {
        ser_writedata64(strm, num);
    }
    return std::vector<unsigned char>(strm.begin(), strm.end());
}


CScript breakable_gp2pkh(const CTokenGroupID &group, const CKeyID &dest, CAmount amt)
{
    CScript script = CScript() << group.bytes() << breakable_SerializeAmount(amt) << OP_GROUP << OP_DROP << OP_DROP
                               << OP_DUP << OP_HASH160 << ToByteVector(dest) << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}


// create a group pay to public key hash script
CScript p2pkh(const CKeyID &dest)
{
    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(dest) << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}

CScript p2sh(const CScriptID &dest)
{
    CScript script;

    script.clear();
    script << OP_HASH160 << ToByteVector(dest) << OP_EQUAL;
    return script;
}

CScript gp2sh(const CTokenGroupID &group, const CScriptID &dest, CAmount amt)
{
    CScript script;
    script.clear();
    script << group.bytes() << SerializeAmount(amt) << OP_GROUP << OP_DROP << OP_DROP << OP_HASH160
           << ToByteVector(dest) << OP_EQUAL;
    return script;
}

std::string HexStr(const CMutableTransaction &tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}


class QuickAddress
{
public:
    QuickAddress()
    {
        secret.MakeNewKey(true);
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CTokenGroupID(addr);
    }
    QuickAddress(const CKey &k)
    {
        secret = k;
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CTokenGroupID(addr);
    }
    QuickAddress(unsigned char key) // make a very simple key for testing only
    {
        secret.MakeNewKey(true);
        unsigned char *c = (unsigned char *)secret.begin();
        *c = key;
        c++;
        for (int i = 1; i < 32; i++, c++)
        {
            *c = 0;
        }
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CTokenGroupID(addr);
    }

    CKey secret;
    CPubKey pubkey;
    CKeyID addr; // 160 bit normal address
    uint256 eAddr; // 256 bit extended address
    CTokenGroupID grp;
};

COutPoint AddUtxo(const CScript &script, uint64_t amount, CCoinsViewCache &coins)
{
    // This creates an unbalanced transaction but it doesn't matter because AddCoins doesn't validate the tx
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = script;
    tx.vout[0].nValue = amount;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    int height = 1; // doesn't matter for our purposes
    AddCoins(coins, tx, height);
    return COutPoint(tx.GetHash(), 0);
}

CTransaction tx1x1(const COutPoint &utxo, const CScript &txo, CAmount amt)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here
    tx.nLockTime = 0;

    return tx;
}

CTransaction tx1x2(const COutPoint &utxo, const CScript &txo, CAmount amt, const CScript &txo2, CAmount amt2)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vin[0].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here
    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vout[1].scriptPubKey = txo2;
    tx.vout[1].nValue = amt2;
    tx.nLockTime = 0;

    return tx;
}
CTransaction tx1x3(const COutPoint &utxo,
    const CScript &txo,
    CAmount amt,
    const CScript &txo2,
    CAmount amt2,
    const CScript &txo3,
    CAmount amt3)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vin[0].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here
    tx.vout.resize(3);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vout[1].scriptPubKey = txo2;
    tx.vout[1].nValue = amt2;
    tx.vout[2].scriptPubKey = txo3;
    tx.vout[2].nValue = amt3;
    tx.nLockTime = 0;
    return tx;
}


CTransaction tx1x1(const COutPoint &utxo,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    const CScript &prevOutScript,
    bool p2pkh = true)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(prevOutScript, tx, 0, sighashType, amt, 0);
    if (!key.Sign(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    }

    return tx;
}

CTransaction tx1x1(const CTransaction &prevtx,
    int prevout,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    bool p2pkh = true)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevtx.GetHash(), prevout);
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(prevtx.vout[prevout].scriptPubKey, tx, 0, sighashType, prevtx.vout[prevout].nValue, 0);
    if (!key.Sign(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    }

    return tx;
}

CTransaction tx1x1_p2sh_of_p2pkh(const CTransaction &prevtx,
    int prevout,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    const CScript &redeemScript)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevtx.GetHash(), prevout);
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(redeemScript, tx, 0, sighashType, prevtx.vout[prevout].nValue, 0);
    if (!key.Sign(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    tx.vin[0].scriptSig << ToByteVector(redeemScript);

    return tx;
}


CTransaction tx1x2(const CTransaction &prevtx,
    int prevout,
    const CScript &txo0,
    CAmount amt0,
    const CScript &txo1,
    CAmount amt1,
    const CKey &key,
    bool p2pkh = true)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevtx.GetHash(), prevout);
    tx.vin[0].scriptSig = CScript();

    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = txo0;
    tx.vout[0].nValue = amt0;
    tx.vout[1].scriptPubKey = txo1;
    tx.vout[1].nValue = amt1;

    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(prevtx.vout[prevout].scriptPubKey, tx, 0, sighashType, prevtx.vout[prevout].nValue, 0);
    if (!key.Sign(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    }

    return tx;
}


class InputData
{
public:
    const CTransaction &prevtx;
    int prevout;
    CKey key;
    bool p2pkh;
    InputData(const CTransaction &prevTx, int prevout, const CKey &key, bool p2pkh = true)
        : prevtx(prevTx), prevout(prevout), key(key), p2pkh(p2pkh)
    {
    }
};

class InputDataCopy : public InputData
{
public:
    CTransaction prevtxStorage;
    InputDataCopy(const CTransaction &prevTx, int prevout, const CKey &key, bool p2pkh = true)
        : InputData(prevtxStorage, prevout, key, p2pkh), prevtxStorage(prevTx)
    {
    }
};

typedef std::pair<CScript, CAmount> OutputData;

CTransaction tx(const std::vector<InputData> in, const std::vector<OutputData> out)
{
    CMutableTransaction tx;
    tx.vin.resize(in.size());
    int idx = 0;
    for (auto i : in)
    {
        tx.vin[idx].prevout = COutPoint(i.prevtx.GetHash(), i.prevout);
        tx.vin[idx].scriptSig = CScript();
        idx++;
    }

    tx.vout.resize(out.size());
    idx = 0;
    for (auto o : out)
    {
        tx.vout[idx].scriptPubKey = o.first;
        tx.vout[idx].nValue = o.second;
        idx++;
    }

    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;

    idx = 0;
    for (auto i : in)
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(
            i.prevtx.vout[i.prevout].scriptPubKey, tx, idx, sighashType, i.prevtx.vout[i.prevout].nValue, 0);
        if (!i.key.Sign(hash, vchSig))
        {
            assert(0);
        }
        vchSig.push_back((unsigned char)sighashType);
        tx.vin[idx].scriptSig << vchSig;
        if (i.p2pkh)
        {
            tx.vin[idx].scriptSig << ToByteVector(i.key.GetPubKey());
        }
        idx++;
    }

    return tx;
}


CTransaction tx2x2(const InputData &in1,
    const InputData &in2,
    const CScript &txo0,
    CAmount amt0,
    const CScript &txo1,
    CAmount amt1)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = COutPoint(in1.prevtx.GetHash(), in1.prevout);
    tx.vin[0].scriptSig = CScript();
    tx.vin[1].prevout = COutPoint(in2.prevtx.GetHash(), in2.prevout);
    tx.vin[1].scriptSig = CScript();

    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = txo0;
    tx.vout[0].nValue = amt0;
    tx.vout[1].scriptPubKey = txo1;
    tx.vout[1].nValue = amt1;

    tx.nLockTime = 0;


    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(
        in1.prevtx.vout[in1.prevout].scriptPubKey, tx, 0, sighashType, in1.prevtx.vout[in1.prevout].nValue, 0);
    if (!in1.key.Sign(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (in1.p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(in1.key.GetPubKey());
    }

    std::vector<unsigned char> vchSig2;
    hash = SignatureHash(
        in2.prevtx.vout[in2.prevout].scriptPubKey, tx, 1, sighashType, in2.prevtx.vout[in2.prevout].nValue, 0);
    if (!in2.key.Sign(hash, vchSig2))
    {
        assert(0);
    }
    vchSig2.push_back((unsigned char)sighashType);

    tx.vin[0].scriptSig << vchSig;
    if (in1.p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(in1.key.GetPubKey());
    }

    tx.vin[1].scriptSig << vchSig2;
    if (in2.p2pkh)
    {
        tx.vin[1].scriptSig << ToByteVector(in2.key.GetPubKey());
    }


    return tx;
}


CTransaction tx2x1(const COutPoint &utxo1, const COutPoint &utxo2, const CScript &txo, CAmount amt)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = utxo1;
    tx.vin[1].prevout = utxo2;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here
    tx.nLockTime = 0;
    return tx;
}

CTransaction tx3x1(const COutPoint &utxo1,
    const COutPoint &utxo2,
    const COutPoint &utxo3,
    const CScript &txo,
    CAmount amt)
{
    CMutableTransaction tx;
    tx.vin.resize(3);
    tx.vin[0].prevout = utxo1;
    tx.vin[1].prevout = utxo2;
    tx.vin[2].prevout = utxo3;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here
    tx.nLockTime = 0;
    return tx;
}

CTransaction tx2x2(const COutPoint &utxo1,
    const COutPoint &utxo2,
    const CScript &txo1,
    CAmount amt1,
    const CScript &txo2,
    CAmount amt2)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = utxo1;
    tx.vin[1].prevout = utxo2;
    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = txo1;
    tx.vout[0].nValue = amt1;
    tx.vin[0].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here
    tx.vout[1].scriptPubKey = txo2;
    tx.vout[1].nValue = amt2;
    tx.vin[1].scriptSig = CScript(); // CheckTokenGroups does not validate sig so anything in here

    tx.nLockTime = 0;
    return tx;
}


CTokenGroupID MakeSubgroup(CTokenGroupID g, int xtra, int size = 0)
{
    int gsize = g.bytes().size();
    if (size == 0)
        size = gsize + 1; // 0 means default which is 1 byte bigger
    std::vector<unsigned char> sgbytes(gsize + size);
    for (int i = 0; i < gsize; i++)
        sgbytes[i] = g.bytes()[i];
    sgbytes[gsize] = xtra;
    for (int i = gsize + 1; i < size; i++)
        sgbytes[i] = 0; // just fill it out
    return CTokenGroupID(sgbytes);
}


BOOST_AUTO_TEST_CASE(tokengroup_basicfunctions)
{
    // Have to enable the function to test it.
    bool opgEnforcing = miningEnforceOpGroup.value;
    miningEnforceOpGroup.value = true;

    CKey secret;
    CPubKey pubkey;
    CKeyID addr;
    uint256 eAddr;
    secret.MakeNewKey(true);
    pubkey = secret.GetPubKey();
    addr = pubkey.GetID();
    eAddr = pubkey.GetHash();

    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(21);
        CScript script = CScript() << fakeGrp << SerializeAmount(100) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                                   << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(19);
        CScript script = CScript() << fakeGrp << SerializeAmount(100) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                                   << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(1);
        CScript script = CScript() << fakeGrp << SerializeAmount(100) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                                   << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(31);
        CScript script = CScript() << fakeGrp << SerializeAmount(100) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                                   << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }

    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(20);
        CScript script = CScript() << fakeGrp << SerializeAmount(100) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                                   << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check correct group length
        std::vector<unsigned char> fakeGrp(32);
        CScript script = CScript() << fakeGrp << SerializeAmount(100) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                                   << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(!ret.isInvalid());
        BOOST_CHECK(ret == CTokenGroupInfo(CTokenGroupID(fakeGrp), GroupAuthorityFlags::NONE));
    }

    { // check CTokenGroupID handling of subgroups
        std::vector<unsigned char> fakeGrp(36);
        for (int i = 0; i < 36; i++)
            fakeGrp[i] = i;
        CTokenGroupID subgrp(fakeGrp);
        BOOST_CHECK(subgrp.isSubgroup());
        BOOST_CHECK(subgrp.parentGroup().bytes().size() == 32);
        CTokenGroupID parentgrp = subgrp.parentGroup();
        for (unsigned int i = 0; i < parentgrp.bytes().size(); i++)
            BOOST_CHECK(parentgrp.bytes()[i] == i);
    }


    { // check P2PKH
        CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(!ret.isInvalid());
        BOOST_CHECK(ret == CTokenGroupInfo(NoGroup, GroupAuthorityFlags::NONE));
    }

    CKey grpSecret;
    CPubKey grpPubkey;
    uint256 grpAddr;
    // uint256 eGrpAddr;
    grpSecret.MakeNewKey(true);
    grpPubkey = secret.GetPubKey();
    // grpAddr = pubkey.GetID();
    // eGrpAddr = pubkey.GetHash();

    { // check GP2PKH
        CScript script = CScript() << ToByteVector(grpAddr) << SerializeAmount(1) << OP_GROUP << OP_DROP << OP_DROP
                                   << OP_DUP << OP_HASH160 << ToByteVector(addr) << OP_EQUALVERIFY << OP_CHECKSIG;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret == CTokenGroupInfo(grpAddr, GroupAuthorityFlags::NONE, 1));
        CTxDestination resultAddr;
        bool worked = ExtractDestination(script, resultAddr);
        BOOST_CHECK(worked && (resultAddr == CTxDestination(addr)));
    }

    { // check P2SH
        CScript script = CScript() << OP_HASH160 << ToByteVector(addr) << OP_EQUAL;
        CTokenGroupInfo ret(script);
        CTokenGroupInfo correct = CTokenGroupInfo(NoGroup, GroupAuthorityFlags::NONE);
        BOOST_CHECK(ret == correct);
    }

    { // check GP2SH
        // cheating here a bit because of course addr should the the hash160 of a script not a pubkey but for this test
        // its just bytes
        CScript script = CScript() << ToByteVector(grpAddr) << SerializeAmount(1000000000UL) << OP_GROUP << OP_DROP
                                   << OP_DROP << OP_HASH160 << ToByteVector(addr) << OP_EQUAL;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret == CTokenGroupInfo(grpAddr, GroupAuthorityFlags::NONE, 1000000000UL));
        CTxDestination resultAddr;
        bool worked = ExtractDestination(script, resultAddr);
        BOOST_CHECK(worked && (resultAddr == CTxDestination(CScriptID(addr))));
    }

    { // check P2TSH  Pay to template script hash
        CScript script = CScript() << OP_HASH256 << ToByteVector(eAddr) << OP_EQUAL;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret == CTokenGroupInfo(NoGroup, GroupAuthorityFlags::NONE));
    }

    { // check GP2TSH
        CScript script = CScript() << ToByteVector(grpAddr) << SerializeAmount(1234567UL) << OP_GROUP << OP_DROP
                                   << OP_HASH256 << ToByteVector(eAddr) << OP_EQUAL;
        CTokenGroupInfo ret(script);
        BOOST_CHECK(ret == CTokenGroupInfo(grpAddr, GroupAuthorityFlags::NONE, 1234567));
    }

    // Now test transaction balances
    {
        CTokenGroupID grp1(1);
        CTokenGroupID grp2(2);
        CTokenGroupID grp3(3);
        QuickAddress u1;
        QuickAddress u2;

        CTokenGroupID subgrp1a = MakeSubgroup(grp1, 1);
        CTokenGroupID subgrp1b = MakeSubgroup(grp1, 2);
        CTokenGroupID subgrp1c = MakeSubgroup(grp1, 2, MAX_SCRIPT_ELEMENT_SIZE);
        CTokenGroupID subgrp1cTooBig = MakeSubgroup(grp1, 2, MAX_SCRIPT_ELEMENT_SIZE + 1);

        // Create a utxo set that I can run tests against
        CCoinsView coinsDummy;
        CCoinsViewCache coins(&coinsDummy);
        CValidationState state;
        COutPoint gutxo = AddUtxo(gp2pkh(grp1, u1.addr, 100), 1, coins);
        COutPoint gutxo_burnable = AddUtxo(gp2pkh(grp1, u1.addr, 100), 2, coins);
        COutPoint mintctrl1 =
            AddUtxo(gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT)), 1, coins);
        COutPoint mintctrl1sg = AddUtxo(
            gp2pkh(grp1, u1.addr,
                toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::SUBGROUP | GroupAuthorityFlags::MINT)),
            1, coins);
        COutPoint mintChildAuth1sg =
            AddUtxo(gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::CCHILD |
                                                   GroupAuthorityFlags::SUBGROUP | GroupAuthorityFlags::MINT)),
                1, coins);
        COutPoint mintChildAuth1 =
            AddUtxo(gp2pkh(grp1, u1.addr,
                        toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT | GroupAuthorityFlags::CCHILD)),
                1, coins);
        COutPoint rescriptChildAuth1 = AddUtxo(
            gp2pkh(grp1, u1.addr,
                toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::CCHILD)),
            1, coins);
        COutPoint rescriptChildAuth1sg =
            AddUtxo(gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::SUBGROUP |
                                                   GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::CCHILD)),
                1, coins);
        COutPoint mintctrl2 =
            AddUtxo(gp2pkh(grp2, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT)), 1, coins);
        COutPoint meltctrl1 =
            AddUtxo(gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MELT)), 1, coins);
        COutPoint meltctrl2 =
            AddUtxo(gp2pkh(grp2, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MELT)), 1, coins);
        COutPoint putxo = AddUtxo(p2pkh(u1.addr), 1, coins);
        COutPoint putxo2 = AddUtxo(p2pkh(u1.addr), 2, coins);

        // my p2sh will just be a p2pkh inside
        CScript p2shBaseScript = p2pkh(u1.addr);
        CScriptID sid = CScriptID(p2shBaseScript);

        COutPoint gp2sh1 = AddUtxo(gp2sh(grp1, sid, 100), 5, coins);
        COutPoint p2sh1 = AddUtxo(p2sh(sid), 1, coins);
        {
            // check mint tx

            // without mint authority
            CTransaction t = tx2x1(putxo2, putxo, gp2pkh(grp1, u1.addr, 100000), 1);
            bool ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // same, grouped
            t = tx2x1(putxo2, putxo, gp2pkh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // with an authority that does not include minting
            t = tx2x1(meltctrl1, putxo, gp2pkh(grp1, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // with minting authority
            t = tx2x1(mintctrl1, putxo, gp2pkh(grp1, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);
            // same, grouped
            t = tx2x1(mintctrl1, putxo, gp2pkh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx2x1(mintctrl1sg, putxo, gp2pkh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);
            t = tx2x1(mintctrl1sg, putxo, gp2pkh(subgrp1c, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // this works because the size limitation enforced during script execution only.
            // token subgroups have no max size...
            t = tx2x1(mintctrl1sg, putxo, gp2pkh(subgrp1cTooBig, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // mint to 2 utxos, 1 is p2sh
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1.addr, 100000), 1, gp2sh(grp1, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1.addr, 100000), 1, gp2sh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx1x2(mintctrl1, gp2pkh(subgrp1b, u1.addr, 100000), 1, gp2sh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx1x2(mintctrl1sg, gp2pkh(grp1, u1.addr, 100000), 1, gp2sh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);
            t = tx1x2(mintctrl1sg, gp2pkh(subgrp1b, u1.addr, 100000), 1, gp2sh(subgrp1a, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // mint to 1 utxos, 2 outputs
            t = tx1x2(mintctrl1, p2pkh(u1.addr), 1, gp2sh(grp1, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);
            // mint to 1 utxos, 2 outputs
            t = tx1x2(mintctrl1, gp2sh(grp1, u1.addr, 100000), 1, p2pkh(u1.addr), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // mint to 2 utxos, 1 group is wrong
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1.addr, 100000), 1, gp2pkh(grp2, u2.addr, 10000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // mint and create child, without auth
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1.addr, 100000), 1,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT)), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // 2 input auths combine into 1 output utxo with both auths
            t = tx2x1(rescriptChildAuth1, mintChildAuth1,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                               GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // Same but rescript is not subgroupable
            t = tx2x1(rescriptChildAuth1, mintChildAuth1sg,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                               GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);
            t = tx2x1(rescriptChildAuth1, mintChildAuth1sg,
                gp2pkh(subgrp1a, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                                   GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx2x1(rescriptChildAuth1sg, mintChildAuth1sg,
                gp2pkh(subgrp1b, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                                   GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // 1 input has child auth, one does not, but output tries to claim both functions
            t = tx2x1(meltctrl1, mintChildAuth1,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                               GroupAuthorityFlags::MELT | GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx2x1(meltctrl1, mintChildAuth1,
                gp2pkh(grp1, u1.addr,
                          toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // 2 input auths combine, but wrong output auth bits
            t = tx2x1(rescriptChildAuth1, mintChildAuth1,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                               GroupAuthorityFlags::MELT | GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // mint and create child, with auth
            t = tx1x2(mintChildAuth1, gp2pkh(grp1, u1.addr, 100000), 1,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT)), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // mint and create child, with auth
            t = tx1x2(mintChildAuth1, gp2pkh(grp1, u1.addr, 100000), 1,
                gp2pkh(grp1, u1.addr, toAmount(GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT |
                                               GroupAuthorityFlags::CCHILD)),
                1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // double mint
            t = tx2x2(mintctrl1, mintctrl2, gp2pkh(grp1, u1.addr, 100000), 1, gp2pkh(grp2, u2.addr, 10000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);


            // double mint 1 wrong group
            t = tx2x2(mintctrl1, mintctrl2, gp2pkh(grp1, u1.addr, 100000), 1, gp2pkh(grp3, u2.addr, 10000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);
        }

        {
            // check p2sh melt
            CTransaction t = tx1x1(gp2sh1, p2pkh(u1.addr), 5);
            bool ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // check p2sh move to another group (should fail)
            t = tx1x1(gp2sh1, gp2pkh(grp2, u1.addr, 100), 5);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            // check p2sh to p2pkh within group controlled by p2sh address
            t = tx1x1(gp2sh1, gp2pkh(grp1, u1.addr, 100), 4);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(ok);

            // check p2sh mint
            t = tx1x1(p2sh1, gp2sh(sid, u1.addr, 100000), 1);
            ok = CheckTokenGroups(t, state, coins);
            BOOST_CHECK(!ok);

            /// TODO check p2sh mint working
        }

        // check same group 1 input 1 output
        CTransaction t = tx1x1(gutxo, gp2pkh(grp1, u1.addr, 100), 1);
        bool ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // check same group 1 input 1 output, wrong value
        t = tx1x1(gutxo, gp2pkh(grp1, u1.addr, 10), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);
        t = tx1x1(gutxo, gp2pkh(grp1, u1.addr, 1000), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // check different groups 1 input 1 output
        t = tx1x1(gutxo, gp2pkh(grp2, u1.addr, 100), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // check mint, incorrect input group address
        t = tx1x1(putxo, gp2pkh(grp2, u1.addr, 100), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // check melt but no authority
        t = tx1x1(gutxo, p2pkh(u2.addr), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // check melt with authority
        t = tx2x1(gutxo, meltctrl1, p2pkh(u1.addr), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // check melt with wrong authority
        t = tx2x1(gutxo, mintctrl1, p2pkh(u1.addr), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // check melt with wrong group authority
        t = tx2x1(gutxo, meltctrl2, p2pkh(u1.addr), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // check burnable utxo but not burning
        t = tx1x1(gutxo_burnable, gp2pkh(grp1, u1.addr, 100), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // Test multiple input/output transactions

        // send 1 coin and melt 100 tokens (with 1 satoshi) into output
        t = tx3x1(putxo, gutxo, meltctrl1, p2pkh(u2.addr), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // this sends 2 satoshi into the fee so it works and melts tokens
        t = tx2x1(gutxo, meltctrl1, p2pkh(u2.addr), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // send 1 coins and melt tokens, but incorrect BCH amount
        // this will work because CheckTokenGroups does not enforce bitcoin balances
        t = tx3x1(putxo, meltctrl1, gutxo, p2pkh(u2.addr), 300);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // partial melt
        t = tx2x2(gutxo, meltctrl1, gp2pkh(grp1, u1.addr, 10), 1, gp2pkh(grp1, u1.addr, 50), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // Exceed input without mint, but in separate outputs with melt authority so if outputs
        // are not combined correctly it would work.
        t = tx2x2(gutxo, meltctrl1, gp2pkh(grp1, u1.addr, 60), 1, gp2pkh(grp1, u1.addr, 50), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // atomic swap tokens
        COutPoint gutxo2 = AddUtxo(gp2pkh(grp2, u2.addr, 100), 1, coins);

        t = tx2x2(gutxo, gutxo2, gp2pkh(grp1, u2.addr, 100), 1, gp2pkh(grp2, u1.addr, 100), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // wrong amounts
        t = tx2x2(gutxo, gutxo2, gp2pkh(grp1, u2.addr, 101), 1, gp2pkh(grp2, u1.addr, 100), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);
        t = tx2x2(gutxo, gutxo2, gp2pkh(grp1, u2.addr, 100), 1, gp2pkh(grp2, u1.addr, 99), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // group transaction with 50 sat fee
        COutPoint p100utxo = AddUtxo(p2pkh(u1.addr), 100, coins);

        t = tx2x2(p100utxo, gutxo, p2pkh(u1.addr), 50, gp2pkh(grp1, u2.addr, 100), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(ok);

        // group transaction with group imbalance
        t = tx2x2(p100utxo, gutxo, p2pkh(u1.addr), 50, gp2pkh(grp1, u2.addr, 101), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);
        // group transaction with group imbalance
        t = tx2x2(p100utxo, gutxo, p2pkh(u1.addr), 50, gp2pkh(grp1, u2.addr, 99), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // Check overflow/underflow errors

        // Check overflow into negative number (2 inputs would sum to a negative)
        COutPoint gutxo3 = AddUtxo(gp2pkh(grp1, u1.addr, std::numeric_limits<CAmount>::max() - 50), 1, coins);
        CAmount amt = std::numeric_limits<CAmount>::max();
        amt += 50;
        t = tx2x1(gutxo3, gutxo, breakable_gp2pkh(grp1, u1.addr, amt), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);
        // Check direct negative number in utxo
        t = tx2x1(gutxo3, gutxo, breakable_gp2pkh(grp1, u1.addr, -300), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // include enough valid utxos to overflow into a valid summed output that equals the input
        t = tx1x3(gutxo, gp2pkh(grp1, u1.addr, std::numeric_limits<CAmount>::max()), 1,
            gp2pkh(grp1, u1.addr, std::numeric_limits<CAmount>::max()), 1, gp2pkh(grp1, u1.addr, 102), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);

        // Add enough positive inputs to overflow into a valid positive number
        COutPoint gutxo4 = AddUtxo(gp2pkh(grp1, u1.addr, std::numeric_limits<CAmount>::max()), 1, coins);
        COutPoint gutxo5 = AddUtxo(gp2pkh(grp1, u1.addr, std::numeric_limits<CAmount>::max()), 1, coins);
        COutPoint gutxo6 = AddUtxo(gp2pkh(grp1, u1.addr, 3), 1, coins);
        // max*2 overflows into negative number + 3 -> 1
        t = tx3x1(gutxo4, gutxo5, gutxo6, gp2pkh(grp1, u1.addr, 1), 1);
        ok = CheckTokenGroups(t, state, coins);
        BOOST_CHECK(!ok);
    }
    miningEnforceOpGroup.value = opgEnforcing;
}

static bool tryBlock(const std::vector<CMutableTransaction> &txns,
    const CScript &scriptPubKey,
    CBlock &result,
    CValidationState &state)
{
    const CChainParams &chainparams = Params();
    CBlockTemplate *pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock &block = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    BOOST_FOREACH (const CMutableTransaction &tx, txns)
        block.vtx.push_back(tx);
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus()))
        ++block.nNonce;

    bool ret;
    ret = ProcessNewBlock(state, chainparams, NULL, &block, true, NULL, false);
    result = block;
    delete pblocktemplate;
    return ret;
}

static bool tryMempool(const CTransaction &tx, CValidationState &state)
{
    LOCK(cs_main);
    bool inputsMissing = false;
    return AcceptToMemoryPool(mempool, state, tx, false, &inputsMissing, true, false);
}


CTokenGroupID findGroupId(const COutPoint &input, TokenGroupIdFlags flags, uint64_t &nonce)
{
    CTokenGroupID ret;
    do
    {
        nonce += 1;
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        // mask off any flags in the nonce
        nonce &= ~((uint64_t)GroupAuthorityFlags::ALL_BITS);
        hasher << input << nonce;
        ret = hasher.GetHash();
    } while (ret.bytes()[31] != (uint8_t)flags);
    return ret;
}


BOOST_FIXTURE_TEST_CASE(tokengroup_blockchain, TestChain100Setup)
{
    // Have to enable the function to test it.
    bool opgEnforcing = miningEnforceOpGroup.value;
    miningEnforceOpGroup.value = true;

    // fPrintToConsole = true;
    // LogToggleCategory(Logging::ALL, true);
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    std::vector<CMutableTransaction> txns;

    QuickAddress p2pkGrp(coinbaseKey);
    QuickAddress grp0(4);
    QuickAddress grp0AllAuth(5);
    QuickAddress grp1AllAuth(6);
    QuickAddress grp1(1);
    QuickAddress a1(2);
    QuickAddress a2(3);

    CValidationState state;
    CBlock blk1;
    CBlock tipblk;
    CBlock badblk; // If I'm expecting a failure, I stick the block in badblk so that I still have the chain tip

    // just regress making a block
    bool ret = tryBlock(txns, p2pkh(grp1.addr), blk1, state);
    BOOST_CHECK(ret);
    if (!ret)
        return; // no subsequent test will work

    txns.push_back(CMutableTransaction()); // Make space for 1 tx in the vector

    {
        // Should fail: bad group size
        uint256 hash = blk1.vtx[0].GetHash();
        std::vector<unsigned char> fakeGrp(21);
        CScript script = CScript() << fakeGrp << OP_GROUP << OP_DROP << OP_DUP << OP_HASH160 << ToByteVector(a1.addr)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

        txns[0] = tx1x1(COutPoint(hash, 0), script, blk1.vtx[0].vout[0].nValue);
        ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
        BOOST_CHECK(!ret);
    }

    // Create group
    uint64_t nonce;
    CTokenGroupID gid = findGroupId(COutPoint(coinbaseTxns[0].GetHash(), 0), TokenGroupIdFlags::NONE, nonce);
    txns[0] = tx1x1(COutPoint(coinbaseTxns[0].GetHash(), 0),
        gp2pkh(gid, grp0AllAuth.addr, authorityFlags(GroupAuthorityFlags::ALL, nonce)), coinbaseTxns[0].vout[0].nValue,
        coinbaseKey, coinbaseTxns[0].vout[0].scriptPubKey, false);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);


    // Mint tokens
    txns[0] = tx({InputData(coinbaseTxns[1], 0, coinbaseKey, false), InputData(tipblk.vtx[1], 0, grp0AllAuth.secret)},
        {OutputData(gp2pkh(gid, grp0AllAuth.addr, authorityFlags(GroupAuthorityFlags::ALL, nonce)), 10000),
            OutputData(gp2pkh(gid, a1.addr, 1000), coinbaseTxns[1].vout[0].nValue - 10000)});
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    CAmount grpInpAmt = coinbaseTxns[1].vout[0].nValue - 10000;
    CAmount grpInpTokAmt = 1000;
    CTransaction grpTx = txns[0];
    InputData grpInp(grpTx, 1, a1.secret);
    InputData grpAuth(grpTx, 0, grp0AllAuth.secret);
    BOOST_CHECK(ret);


    // Mint tokens without auth
    txns[0] = tx({InputData(coinbaseTxns[2], 0, coinbaseKey, false)},
        {OutputData(gp2pkh(gid, a1.addr, 1000), coinbaseTxns[2].vout[0].nValue - 10000)});
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // Useful printouts:
    // Note state response is broken due to state = CValidationState(); in main.cpp:ActivateBestChainStep
    // printf("state: %d:%s, %s\n", state.GetRejectCode(), state.GetRejectReason().c_str(),
    // state.GetDebugMessage().c_str())
    // printf("%s\n", CTransaction(txns[0]).ToString().c_str());
    // printf("%s\n", HexStr(txns[0]).c_str());
    // printf("state: %d:%s, %s\n", state.GetRejectCode(), state.GetRejectReason().c_str(),
    // state.GetDebugMessage().c_str());

    // Create another group, use different grp as 0 input tx (shouldn't matter)
    nonce = 0xfffffffffff00000ULL; // start anywhere
    CTokenGroupID gid1 = findGroupId(COutPoint(coinbaseTxns[3].GetHash(), 0), TokenGroupIdFlags::NONE, nonce);
    txns[0] = tx({InputData(coinbaseTxns[3], 0, coinbaseKey, false)},
        {OutputData(gp2pkh(gid1, grp1AllAuth.addr, authorityFlags(GroupAuthorityFlags::ALL, nonce)), 1),
            OutputData(p2pkh(a2.addr), coinbaseTxns[3].vout[0].nValue - 1)});
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);

    // Should fail: pay from group to non-groups
    txns[0] = tx({grpInp}, {OutputData(p2pkh(a2.addr), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the correct group, wrong group qty
    txns[0] = tx({grpInp}, {OutputData(gp2pkh(gid, a2.addr, grpInpTokAmt - 1), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the correct group, wrong group qty
    txns[0] = tx({grpInp}, {OutputData(gp2pkh(gid, a2.addr, grpInpTokAmt + 1), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the correct group, wrong group qty
    txns[0] = tx({grpInp},
        {
            OutputData(gp2pkh(gid, a2.addr, grpInpTokAmt - 1), grpInpAmt - 100),
            OutputData(gp2pkh(gid, a1.addr, 2), 10),
        });
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the wrong group, correct qty
    txns[0] = tx({grpInp}, {OutputData(gp2pkh(gid1, a2.addr, grpInpTokAmt), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);


    // now correct group spend in various ways
    txns[0] = tx({grpInp},
        {
            OutputData(gp2pkh(gid, a2.addr, grpInpTokAmt / 2), grpInpAmt - 100),
            OutputData(gp2pkh(gid, a1.addr, grpInpTokAmt / 2), 10),
        });
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(ret);

    InputDataCopy toks(txns[0], 0, a2.secret);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);


    // To make sure blocks get accepted or rejected without the block's tx in the mempool, I
    // won't use the mempool for the rest of this test.

    // Melt (and lose the authority)
    txns[0] = tx({grpAuth, toks}, {OutputData(gp2pkh(gid, a1.addr, 1), 2)});
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);

#if 0 // TODO not converted
    // P2SH
    CScript p2shBaseScript1 = p2pkh(a1.addr);
    CScriptID sid1 = CScriptID(p2shBaseScript1);
    CScript p2shBaseScript2 = p2pkh(a2.addr);
    CScriptID sid2 = CScriptID(p2shBaseScript2);

    // Spend to a p2sh address so we can tokenify it
    txns[0] = tx1x1(COutPoint(coinbaseTxns[1].GetHash(), 0), p2sh(sid1), coinbaseTxns[1].vout[0].nValue, coinbaseKey,
        coinbaseTxns[1].vout[0].scriptPubKey, false);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);

    // Mint without permission
    txns[0] = tx1x1_p2sh_of_p2pkh(
        tipblk.vtx[1], 0, gp2sh(sid2, sid2, 10000), tipblk.vtx[1].vout[0].nValue, a1.secret, p2shBaseScript1);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // Mint to a different p2sh destination
    txns[0] = tx1x1_p2sh_of_p2pkh(
        tipblk.vtx[1], 0, gp2sh(sid1, sid2, 10000), tipblk.vtx[1].vout[0].nValue, a1.secret, p2shBaseScript1);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);

    // FAIL: Spend that gp2sh to a p2pkh, still under the group controlled by a p2sh address
    txns[0] =
        tx1x1_p2sh_of_p2pkh(tipblk.vtx[1], 0, p2pkh(a1.addr), tipblk.vtx[1].vout[0].nValue, a2.secret, p2shBaseScript2);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // FAIL: Spend that gp2sh to a p2sh
    txns[0] =
        tx1x1_p2sh_of_p2pkh(tipblk.vtx[1], 0, p2sh(sid1), tipblk.vtx[1].vout[0].nValue, a2.secret, p2shBaseScript2);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // Spend that gp2sh to a gp2pkh, bad group qty
    txns[0] = tx1x1_p2sh_of_p2pkh(
        tipblk.vtx[1], 0, gp2pkh(sid1, a1.addr, 1000), tipblk.vtx[1].vout[0].nValue, a2.secret, p2shBaseScript2);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // Spend that gp2sh to a gp2pkh, still under the group controlled by a p2sh address
    txns[0] = tx1x1_p2sh_of_p2pkh(
        tipblk.vtx[1], 0, gp2pkh(sid1, a1.addr, 10000), tipblk.vtx[1].vout[0].nValue, a2.secret, p2shBaseScript2);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);

    // FAIL: Spend back into the controlling non-grouped p2sh
    txns[0] = tx1x1(tipblk.vtx[1], 0, p2sh(sid1), tipblk.vtx[1].vout[0].nValue, a1.secret);
    ret = tryBlock(txns, p2pkh(a2.addr), badblk, state);
    BOOST_CHECK(!ret);

    // Spend back into the controlling p2sh
    txns[0] = tx1x1(tipblk.vtx[1], 0, gp2sh(sid1, sid1, 10000), tipblk.vtx[1].vout[0].nValue, a1.secret);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);

    // melt into bch
    txns[0] =
        tx1x1_p2sh_of_p2pkh(tipblk.vtx[1], 0, p2pkh(a2.addr), tipblk.vtx[1].vout[0].nValue, a1.secret, p2shBaseScript1);
    ret = tryBlock(txns, p2pkh(a2.addr), tipblk, state);
    BOOST_CHECK(ret);
#endif

    miningEnforceOpGroup.value = opgEnforcing;
}


BOOST_AUTO_TEST_SUITE_END()
