// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017 The PIVX developers
// Copyright (c) 2018-2019 The Ion developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "base58.h"
#include "consensus/tokengroups.h"
#include "ionaddrenc.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include "tokens/tokengroupdescription.h"
#include <univalue.h>
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

std::string FormatScript(const CScript& script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_CHECKMULTISIGVERIFY) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            } else {
                ret += strprintf("0x%x", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

std::string EncodeHexTx(const CTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey,
    UniValue& out,
    bool fIncludeHex)
{
    txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", scriptPubKey.ToString());
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.pushKV("addresses", a);
}

void TokenTxnoutToUniv(const CTxOut& txout,
    UniValue& out, bool& fExpectFirstOpReturn)
{
    CTokenGroupInfo tokenGroupInfo(txout.scriptPubKey);

    if (fExpectFirstOpReturn && (txout.nValue == 0) && (txout.scriptPubKey[0] == OP_RETURN)) {
        fExpectFirstOpReturn = false;

        CTokenGroupDescription tokenGroupDescription = CTokenGroupDescription(txout.scriptPubKey);

        out.pushKV("outputType", "description");
        out.pushKV("ticker", tokenGroupDescription.strTicker);
        out.pushKV("name", tokenGroupDescription.strName);
        out.pushKV("decimalPos", tokenGroupDescription.nDecimalPos);
        out.pushKV("URL", tokenGroupDescription.strDocumentUrl);
        out.pushKV("documentHash", tokenGroupDescription.documentHash.ToString());
    } else if (!tokenGroupInfo.invalid && tokenGroupInfo.associatedGroup != NoGroup) {
        if (tokenGroupInfo.associatedGroup.isSubgroup()) {
            CTokenGroupID parentgrp = tokenGroupInfo.associatedGroup.parentGroup();
            out.pushKV("parentGroupID", EncodeTokenGroup(parentgrp));
        }
        out.pushKV("groupID", EncodeTokenGroup(tokenGroupInfo.associatedGroup));
        if (tokenGroupInfo.isAuthority()){
            out.pushKV("outputType", "authority");
            out.pushKV("authorities", EncodeGroupAuthority(tokenGroupInfo.controllingGroupFlags()));
        } else {
            out.pushKV("outputType", "amount");
            out.pushKV("amount", tokenGroupInfo.getAmount());
        }
    }
}

void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION));
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin(UniValue::VARR);
    for (const CTxIn& txin : tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", txin.scriptSig.ToString());
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    CScript firstOpReturn;
    bool fIsGroupConfigurationTX = IsAnyOutputGroupedCreation(tx);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);

        UniValue t(UniValue::VOBJ);
        TokenTxnoutToUniv(txout, t, fIsGroupConfigurationTX);
        if (t.size() > 0)
            out.pushKV("token", t);

        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    if (hashBlock != 0)
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
