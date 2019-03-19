// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "wallet/tokengroupwallet.h"
#include "base58.h"
#include "ionaddrenc.h"
#include "coincontrol.h"
#include "coins.h"
#include "consensus/tokengroups.h"
#include "consensus/validation.h"
#include "dstencode.h"
#include "init.h"
#include "main.h" // for BlockMap
#include "primitives/transaction.h"
#include "pubkey.h"
#include "random.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "tokengroupmanager.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include <algorithm>

#include <boost/lexical_cast.hpp>

// allow this many times fee overpayment, rather than make a change output
#define FEE_FUDGE 2

UniValue groupedlistsinceblock(const UniValue &params, bool fHelp);
UniValue groupedlisttransactions(const UniValue &params, bool fHelp);

// Number of satoshis we will put into a grouped output
static const CAmount GROUPED_SATOSHI_AMT = 1;

// Approximate size of signature in a script -- used for guessing fees
const unsigned int TX_SIG_SCRIPT_LEN = 72;

/* Grouped transactions look like this:

GP2PKH:

OP_DATA(group identifier)
OP_DATA(SerializeAmount(amount))
OP_GROUP
OP_DROP
OP_DUP
OP_HASH160
OP_DATA(pubkeyhash)
OP_EQUALVERIFY
OP_CHECKSIG

GP2SH:

OP_DATA(group identifier)
OP_DATA(CompactSize(amount))
OP_GROUP
OP_DROP
OP_HASH160 [20-byte-hash-value] OP_EQUAL

FUTURE: GP2SH version 2:

OP_DATA(group identifier)
OP_DATA(CompactSize(amount))
OP_GROUP
OP_DROP
OP_HASH256 [32-byte-hash-value] OP_EQUAL
*/

class CTxDestinationTokenGroupExtractor : public boost::static_visitor<CTokenGroupID>
{
public:
    CTokenGroupID operator()(const CKeyID &id) const { return CTokenGroupID(id); }
    CTokenGroupID operator()(const CScriptID &id) const { return CTokenGroupID(id); }
    CTokenGroupID operator()(const CNoDestination &) const { return CTokenGroupID(); }
};

CTokenGroupID GetTokenGroup(const CTxDestination &id)
{
    return boost::apply_visitor(CTxDestinationTokenGroupExtractor(), id);
}

CTxDestination ControllingAddress(const CTokenGroupID &grp, txnouttype addrType)
{
    const std::vector<unsigned char> &data = grp.bytes();
    if (data.size() != 20) // this is a single mint so no controlling address
        return CNoDestination();
    if (addrType == TX_SCRIPTHASH)
        return CTxDestination(CScriptID(uint160(data)));
    return CTxDestination(CKeyID(uint160(data)));
}

CTokenGroupID GetTokenGroup(const std::string &addr, const CChainParams &params)
{
    IONAddrContent cac = DecodeIONAddrContent(addr, params);
    if (cac.type == IONAddrType::GROUP_TYPE)
        return CTokenGroupID(cac.hash);
    // otherwise it becomes NoGroup (i.e. data is size 0)
    return CTokenGroupID();
}

std::string EncodeTokenGroup(const CTokenGroupID &grp, const CChainParams &params)
{
    return EncodeIONAddr(grp.bytes(), IONAddrType::GROUP_TYPE, params);
}


class CGroupScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
    CTokenGroupID group;
    CAmount quantity;

public:
    CGroupScriptVisitor(CTokenGroupID grp, CAmount qty, CScript *scriptin) : group(grp), quantity(qty)
    {
        script = scriptin;
    }
    bool operator()(const CNoDestination &dest) const
    {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const
    {
        script->clear();
        if (group.isUserGroup())
        {
            *script << group.bytes() << SerializeAmount(quantity) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                    << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        }
        else
        {
            *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        }
        return true;
    }

    bool operator()(const CScriptID &scriptID) const
    {
        script->clear();
        if (group.isUserGroup())
        {
            *script << group.bytes() << SerializeAmount(quantity) << OP_GROUP << OP_DROP << OP_DROP << OP_HASH160
                    << ToByteVector(scriptID) << OP_EQUAL;
        }
        else
        {
            *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        }
        return true;
    }
};

void GetAllGroupBalances(const CWallet *wallet, std::unordered_map<CTokenGroupID, CAmount> &balances)
{
    std::vector<COutput> coins;
    wallet->FilterCoins(coins, [&balances](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if ((tg.associatedGroup != NoGroup) && !tg.isAuthority()) // must be sitting in any group address
        {
            if (tg.quantity > std::numeric_limits<CAmount>::max() - balances[tg.associatedGroup])
                balances[tg.associatedGroup] = std::numeric_limits<CAmount>::max();
            else
                balances[tg.associatedGroup] += tg.quantity;
        }
        return false; // I don't want to actually filter anything
    });
}

CAmount GetGroupBalance(const CTokenGroupID &grpID, const CTxDestination &dest, const CWallet *wallet)
{
    std::vector<COutput> coins;
    CAmount balance = 0;
    wallet->FilterCoins(coins, [grpID, dest, &balance](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if ((grpID == tg.associatedGroup) && !tg.isAuthority()) // must be sitting in group address
        {
            bool useit = dest == CTxDestination(CNoDestination());
            if (!useit)
            {
                CTxDestination address;
                txnouttype whichType;
                if (ExtractDestinationAndType(out->scriptPubKey, address, whichType))
                {
                    if (address == dest)
                        useit = true;
                }
            }
            if (useit)
            {
                if (tg.quantity > std::numeric_limits<CAmount>::max() - balance)
                    balance = std::numeric_limits<CAmount>::max();
                else
                    balance += tg.quantity;
            }
        }
        return false;
    });
    return balance;
}

CScript GetScriptForDestination(const CTxDestination &dest, const CTokenGroupID &group, const CAmount &amount)
{
    CScript script;

    boost::apply_visitor(CGroupScriptVisitor(group, amount, &script), dest);
    return script;
}

static GroupAuthorityFlags ParseAuthorityParams(const UniValue &params, unsigned int &curparam)
{
    GroupAuthorityFlags flags = GroupAuthorityFlags::CTRL | GroupAuthorityFlags::CCHILD;
    while (1)
    {
        std::string sflag;
        std::string p = params[curparam].get_str();
        std::transform(p.begin(), p.end(), std::back_inserter(sflag), ::tolower);
        if (sflag == "mint")
            flags |= GroupAuthorityFlags::MINT;
        else if (sflag == "melt")
            flags |= GroupAuthorityFlags::MELT;
        else if (sflag == "nochild")
            flags &= ~GroupAuthorityFlags::CCHILD;
        else if (sflag == "child")
            flags |= GroupAuthorityFlags::CCHILD;
        else if (sflag == "rescript")
            flags |= GroupAuthorityFlags::RESCRIPT;
        else if (sflag == "subgroup")
            flags |= GroupAuthorityFlags::SUBGROUP;
        else
            break; // If param didn't match, then return because we've left the list of flags
        curparam++;
        if (curparam >= params.size())
            break;
    }
    return flags;
}

// extracts a common RPC call parameter pattern.  Returns curparam.
static unsigned int ParseGroupAddrValue(const UniValue &params,
    unsigned int curparam,
    CTokenGroupID &grpID,
    std::vector<CRecipient> &outputs,
    CAmount &totalValue,
    bool groupedOutputs)
{
    grpID = GetTokenGroup(params[curparam].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    outputs.reserve(params.size() / 2);
    curparam++;
    totalValue = 0;
    while (curparam + 1 < params.size())
    {
        CTxDestination dst = DecodeDestination(params[curparam].get_str(), Params());
        if (dst == CTxDestination(CNoDestination()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address");
        }
        CAmount amount = tokenGroupManager->AmountFromTokenValue(params[curparam + 1], grpID);
        if (amount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid parameter: amount");
        CScript script;
        CRecipient recipient;
        if (groupedOutputs)
        {
            script = GetScriptForDestination(dst, grpID, amount);
            recipient = {script, GROUPED_SATOSHI_AMT, false};
        }
        else
        {
            script = GetScriptForDestination(dst, NoGroup, 0);
            recipient = {script, amount, false};
        }

        totalValue += amount;
        outputs.push_back(recipient);
        curparam += 2;
    }
    return curparam;
}

bool NearestGreaterCoin(const std::vector<COutput> &coins, CAmount amt, COutput &chosenCoin)
{
    bool ret = false;
    CAmount curBest = std::numeric_limits<CAmount>::max();

    for (const auto &coin : coins)
    {
        CAmount camt = coin.GetValue();
        if ((camt > amt) && (camt < curBest))
        {
            curBest = camt;
            chosenCoin = coin;
            ret = true;
        }
    }

    return ret;
}


CAmount CoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins)
{
    // simple algorithm grabs until amount exceeded
    CAmount cur = 0;

    for (const auto &coin : coins)
    {
        chosenCoins.push_back(coin);
        cur += coin.GetValue();
        if (cur >= amt)
            break;
    }
    return cur;
}

CAmount GroupCoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins)
{
    // simple algorithm grabs until amount exceeded
    CAmount cur = 0;

    for (const auto &coin : coins)
    {
        chosenCoins.push_back(coin);
        CTokenGroupInfo tg(coin.tx->vout[coin.i].scriptPubKey);
        cur += tg.quantity;
        if (cur >= amt)
            break;
    }
    return cur;
}

uint64_t RenewAuthority(const COutput &authority, std::vector<CRecipient> &outputs, CReserveKey &childAuthorityKey)
{
    // The melting authority is consumed.  A wallet can decide to create a child authority or not.
    // In this simple wallet, we will always create a new melting authority if we spend a renewable
    // (CCHILD is set) one.
    uint64_t totalBchNeeded = 0;
    CTokenGroupInfo tg(authority.GetScriptPubKey());

    if (tg.allowsRenew())
    {
        // Get a new address from the wallet to put the new mint authority in.
        CPubKey pubkey;
        childAuthorityKey.GetReservedKey(pubkey);
        CTxDestination authDest = pubkey.GetID();
        CScript script = GetScriptForDestination(authDest, tg.associatedGroup, (CAmount)(tg.controllingGroupFlags() & GroupAuthorityFlags::ALL_BITS));
        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
        outputs.push_back(recipient);
        totalBchNeeded += GROUPED_SATOSHI_AMT;
    }

    return totalBchNeeded;
}

void ConstructTx(CWalletTx &wtxNew,
    const std::vector<COutput> &chosenCoins,
    const std::vector<CRecipient> &outputs,
    CAmount totalAvailable,
    CAmount totalNeeded,
    CAmount totalGroupedAvailable,
    CAmount totalGroupedNeeded,
    CTokenGroupID grpID,
    CWallet *wallet)
{
    std::string strError;
    CMutableTransaction tx;
    CReserveKey groupChangeKeyReservation(wallet);
    CReserveKey feeChangeKeyReservation(wallet);

    {
        unsigned int approxSize = 0;

        // Add group outputs based on the passed recipient data to the tx.
        for (const CRecipient &recipient : outputs)
        {
            CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
            tx.vout.push_back(txout);
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
        }

        // Gather data on the provided inputs, and add them to the tx.
        unsigned int inpSize = 0;
        for (const auto &coin : chosenCoins)
        {
            CTxIn txin(coin.GetOutPoint());
            tx.vin.push_back(txin);
            inpSize = ::GetSerializeSize(txin, SER_DISK, CLIENT_VERSION) + TX_SIG_SCRIPT_LEN;
            approxSize += inpSize;
        }

        if (totalGroupedAvailable > totalGroupedNeeded) // need to make a group change output
        {
            CPubKey newKey;

            if (!groupChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(GROUPED_SATOSHI_AMT,
                GetScriptForDestination(newKey.GetID(), grpID, totalGroupedAvailable - totalGroupedNeeded));
            tx.vout.push_back(txout);
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
        }

        // Add another input for the bitcoin used for the fee
        // this ignores the additional change output
        approxSize += inpSize * 3;

        // Now add bitcoin fee
        CAmount fee = wallet->GetRequiredFee(approxSize);

        if (totalAvailable < totalNeeded + fee) // need to find a fee input
        {
            // find a fee input
            std::vector<COutput> bchcoins;
            wallet->FilterCoins(bchcoins, [](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                return NoGroup == tg.associatedGroup;
            });

            COutput feeCoin(nullptr, 0, 0, false);
            if (!NearestGreaterCoin(bchcoins, fee, feeCoin))
            {
                strError = strprintf("Not enough funds for fee of %d.", FormatMoney(fee));
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
            }

            CTxIn txin(feeCoin.GetOutPoint(), CScript(), std::numeric_limits<unsigned int>::max() - 1);
            tx.vin.push_back(txin);
            totalAvailable += feeCoin.GetValue();
        }

        // make change if input is too big -- its okay to overpay by FEE_FUDGE rather than make dust.
        if (totalAvailable > totalNeeded + (FEE_FUDGE * fee))
        {
            CPubKey newKey;

            if (!feeChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(totalAvailable - totalNeeded - fee, GetScriptForDestination(newKey.GetID()));
            tx.vout.push_back(txout);
        }

        if (!wallet->SignTransaction(tx))
        {
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing transaction failed");
        }
    }

    wtxNew.BindWallet(wallet);
    wtxNew.fFromMe = true;
    *static_cast<CTransaction *>(&wtxNew) = CTransaction(tx);
    // I'll manage my own keys because I have multiple.  Passing a valid key down breaks layering.
    CReserveKey dummy(wallet);
    if (!wallet->CommitTransaction(wtxNew, dummy))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the "
                                             "coins in your wallet were already spent, such as if you used a copy of "
                                             "wallet.dat and coins were spent in the copy but not marked as spent "
                                             "here.");

    feeChangeKeyReservation.KeepKey();
    groupChangeKeyReservation.KeepKey();
}


void GroupMelt(CWalletTx &wtxNew, const CTokenGroupID &grpID, CAmount totalNeeded, CWallet *wallet)
{
    std::string strError;
    std::vector<CRecipient> outputs; // Melt has no outputs (except change)
    CAmount totalAvailable = 0;
    CAmount totalBchAvailable = 0;
    CAmount totalBchNeeded = 0;
    LOCK2(cs_main, wallet->cs_wallet);

    // Find melt authority
    std::vector<COutput> coins;

    int nOptions = wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if ((tg.associatedGroup == grpID) && tg.allowsMelt())
        {
            return true;
        }
        return false;
    });

    // if its a subgroup look for a parent authority that will work
    // As an idiot-proofing step, we only allow parent authorities that can be renewed, but that is a
    // preference coded in this wallet, not a group token requirement.
    if ((nOptions == 0) && (grpID.isSubgroup()))
    {
        // if its a subgroup look for a parent authority that will work
        nOptions = wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
            CTokenGroupInfo tg(out->scriptPubKey);
            if (tg.isAuthority() && tg.allowsRenew() && tg.allowsSubgroup() && tg.allowsMelt() &&
                (tg.associatedGroup == grpID.parentGroup()))
            {
                return true;
            }
            return false;
        });
    }

    if (nOptions == 0)
    {
        strError = _("To melt coins, an authority output with melt capability is needed.");
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }
    COutput authority(nullptr, 0, 0, false);
    // Just pick the first one for now.
    for (auto coin : coins)
    {
        totalBchAvailable += coin.tx->vout[coin.i].nValue; // The melt authority may have some BCH in it
        authority = coin;
        break;
    }

    // Find meltable coins
    coins.clear();
    wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        // must be a grouped output sitting in group address
        return ((grpID == tg.associatedGroup) && !tg.isAuthority());
    });

    // Get a near but greater quantity
    std::vector<COutput> chosenCoins;
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    if (totalAvailable < totalNeeded)
    {
        std::string strError;
        strError = strprintf("Not enough tokens in the wallet.  Need %d more.", totalNeeded - totalAvailable);
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    chosenCoins.push_back(authority);

    CReserveKey childAuthorityKey(wallet);
    totalBchNeeded += RenewAuthority(authority, outputs, childAuthorityKey);
    // by passing a fewer tokens available than are actually in the inputs, there is a surplus.
    // This surplus will be melted.
    ConstructTx(wtxNew, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, totalAvailable - totalNeeded, 0, grpID,
        wallet);
    childAuthorityKey.KeepKey();
}

void GroupSend(CWalletTx &wtxNew,
    const CTokenGroupID &grpID,
    const std::vector<CRecipient> &outputs,
    CAmount totalNeeded,
    CWallet *wallet)
{
    LOCK2(cs_main, wallet->cs_wallet);
    std::string strError;
    std::vector<COutput> coins;
    CAmount totalAvailable = 0;
    wallet->FilterCoins(coins, [grpID, &totalAvailable](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if ((grpID == tg.associatedGroup) && !tg.isAuthority())
        {
            totalAvailable += tg.quantity;
            return true;
        }
        return false;
    });

    if (totalAvailable < totalNeeded)
    {
        strError = strprintf("Not enough tokens in the wallet.  Need %d more.", totalNeeded - totalAvailable);
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    // Get a near but greater quantity
    std::vector<COutput> chosenCoins;
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    ConstructTx(wtxNew, chosenCoins, outputs, 0, GROUPED_SATOSHI_AMT * outputs.size(), totalAvailable, totalNeeded,
        grpID, wallet);
}

std::vector<std::vector<unsigned char> > ParseGroupDescParams(const UniValue &params, unsigned int &curparam)
{
    std::vector<std::vector<unsigned char> > ret;
    std::string tickerStr = params[curparam].get_str();
    if (tickerStr.size() > 8)
    {
        std::string strError = strprintf("Ticker %s has too many characters (8 max)", tickerStr);
        throw JSONRPCError(RPC_INVALID_PARAMS, strError);
    }
    ret.push_back(std::vector<unsigned char>(tickerStr.begin(), tickerStr.end()));

    curparam++;
    if (curparam >= params.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameter: token name");
    }

    std::string name = params[curparam].get_str();
    ret.push_back(std::vector<unsigned char>(name.begin(), name.end()));
    curparam++;
    // we will accept just ticker and name
    if (curparam >= params.size())
    {
        ret.push_back(std::vector<unsigned char>());
        ret.push_back(std::vector<unsigned char>());
        ret.push_back(std::vector<unsigned char>());
        return ret;
    }

    uint64_t lDecimalPosition = params[curparam].get_int64();
    if (lDecimalPosition > 16) {
        std::string strError = strprintf("Parameter %d is too large, maximum is 16", lDecimalPosition);
        throw JSONRPCError(RPC_INVALID_PARAMS, strError);
    }
    ret.push_back(std::vector<unsigned char>({(unsigned char)lDecimalPosition}));
    curparam++;

    // we will accept just ticker, name and decimal position
    if (curparam >= params.size())
    {
        ret.push_back(std::vector<unsigned char>());
        ret.push_back(std::vector<unsigned char>());
        return ret;
    }

    std::string url = params[curparam].get_str();
    // we could do a complete URL validity check here but for now just check for :
    if (url.find(":") == std::string::npos)
    {
        std::string strError = strprintf("Parameter %s is not a URL, missing colon", url);
        throw JSONRPCError(RPC_INVALID_PARAMS, strError);
    }
    ret.push_back(std::vector<unsigned char>(url.begin(), url.end()));

    curparam++;
    if (curparam >= params.size())
    {
        // If you have a URL to the TDD, you need to have a hash or the token creator
        // could change the document without holders knowing about it.
        throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameter: token description document hash");
    }

    std::string hexDocHash = params[curparam].get_str();
    uint256 docHash;
    docHash.SetHex(hexDocHash);
    ret.push_back(std::vector<unsigned char>(docHash.begin(), docHash.end()));
    return ret;
}

CScript BuildTokenDescScript(const std::vector<std::vector<unsigned char> > &desc)
{
    CScript ret;
    std::vector<unsigned char> data;
    // github.com/bitcoincashorg/bitcoincash.org/blob/master/etc/protocols.csv
    uint32_t OpRetGroupId = 88888888; // see https:
    ret << OP_RETURN << OpRetGroupId;
    for (auto &d : desc)
    {
        ret << d;
    }
    return ret;
}

CTokenGroupID findGroupId(const COutPoint &input, CScript opRetTokDesc, TokenGroupIdFlags flags, uint64_t &nonce)
{
    CTokenGroupID ret;
    do
    {
        nonce += 1;
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        // mask off any flags in the nonce
        nonce &= ~((uint64_t)GroupAuthorityFlags::ALL_BITS);
        hasher << input;

        if (opRetTokDesc.size())
        {
            std::vector<unsigned char> data(opRetTokDesc.begin(), opRetTokDesc.end());
            hasher << data;
        }
        hasher << nonce;
        ret = hasher.GetHash();
    } while (ret.bytes()[31] != (uint8_t)flags);
    return ret;
}

extern UniValue token(const UniValue &params, bool fHelp)
{
    CWallet *wallet = pwalletMain;
    if (!pwalletMain)
        return NullUniValue;

    if (fHelp || params.size() < 1)
        throw std::runtime_error(
            "token [new, mint, melt, send] \n"
            "\nToken functions.\n"
            "'new' creates a new token type. args: authorityAddress\n"
            "'mint' creates new tokens. args: groupId address quantity\n"
            "'melt' removes tokens from circulation. args: groupId quantity\n"
            "'balance' reports quantity of this token. args: groupId [address]\n"
            "'send' sends tokens to a new address. args: groupId address quantity [address quantity...]\n"
            "'authority create' creates a new authority args: groupId address [mint melt nochild rescript]\n"
            "'subgroup' translates a group and additional data into a subgroup identifier. args: groupId data\n"
            "\nArguments:\n"
            "1. \"groupId\"     (string, required) the group identifier\n"
            "2. \"address\"     (string, required) the destination address\n"
            "3. \"quantity\"    (numeric, required) the quantity desired\n"
            "4. \"data\"        (number, 0xhex, or string) binary data\n"
            "\nResult:\n"
            "\n"
            "\nExamples:\n"
            "\nCreate a transaction with no inputs\n" +
            HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
            "\nAdd sufficient unsigned inputs to meet the output value\n" +
            HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") + "\nSign the transaction\n" +
            HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") + "\nSend the transaction\n" +
            HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\""));

    std::string operation;
    std::string p0 = params[0].get_str();
    std::transform(p0.begin(), p0.end(), std::back_inserter(operation), ::tolower);
    EnsureWalletIsUnlocked();

    if (operation == "listsinceblock")
    {
        return groupedlistsinceblock(params, fHelp);
    }
    if (operation == "listtransactions")
    {
        return groupedlisttransactions(params, fHelp);
    }
    if (operation == "subgroup")
    {
        unsigned int curparam = 1;
        if (curparam >= params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameters");
        }
        CTokenGroupID grpID;
        std::vector<unsigned char> postfix;
        // Get the group id from the command line
        grpID = GetTokenGroup(params[curparam].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }
        curparam++;

        int64_t postfixNum = 0;
        bool isNum = false;
        if (params[curparam].isNum())
        {
            postfixNum = params[curparam].get_int64();
            isNum = true;
        }
        else // assume string
        {
            std::string postfixStr = params[curparam].get_str();
            if ((postfixStr[0] == '0') && (postfixStr[0] == 'x'))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: Hex not implemented yet");
            }
            try
            {
                postfixNum = boost::lexical_cast<int64_t>(postfixStr);
                isNum = true;
            }
            catch (const boost::bad_lexical_cast &)
            {
                for (unsigned int i = 0; i < postfixStr.size(); i++)
                    postfix.push_back(postfixStr[i]);
            }
        }

        if (isNum)
        {
            CDataStream ss(0, 0);
            uint64_t xSize = postfixNum;
            WRITEDATA(ss, xSize);
//            ser_writedata64(ss, postfixNum);
            for (auto c : ss)
                postfix.push_back(c);
        }

        if (postfix.size() == 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: no subgroup postfix provided");
        }
        std::vector<unsigned char> subgroupbytes(grpID.bytes().size() + postfix.size());
        unsigned int i;
        for (i = 0; i < grpID.bytes().size(); i++)
        {
            subgroupbytes[i] = grpID.bytes()[i];
        }
        for (unsigned int j = 0; j < postfix.size(); j++, i++)
        {
            subgroupbytes[i] = postfix[j];
        }
        CTokenGroupID subgrpID(subgroupbytes);
        return EncodeTokenGroup(subgrpID);
    }
    else if (operation == "authority")
    {
        LOCK2(cs_main, wallet->cs_wallet);
        CAmount totalBchNeeded = 0;
        CAmount totalBchAvailable = 0;
        unsigned int curparam = 1;
        std::vector<COutput> chosenCoins;
        std::vector<CRecipient> outputs;
        if (curparam >= params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameters");
        }
        std::string suboperation;
        std::string p1 = params[curparam].get_str();
        std::transform(p1.begin(), p1.end(), std::back_inserter(suboperation), ::tolower);
        curparam++;
        if (suboperation == "create")
        {
            CTokenGroupID grpID;
            GroupAuthorityFlags auth = GroupAuthorityFlags();
            // Get the group id from the command line
            grpID = GetTokenGroup(params[curparam].get_str());
            if (!grpID.isUserGroup())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
            }

            // Get the destination address from the command line
            curparam++;
            CTxDestination dst = DecodeDestination(params[curparam].get_str(), Params());
            if (dst == CTxDestination(CNoDestination()))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address");
            }

            // Get what authority permissions the user wants from the command line
            curparam++;
            if (curparam < params.size()) // If flags are not specified, we dup existing flags.
            {
                auth = ParseAuthorityParams(params, curparam);
                if (curparam < params.size())
                {
                    std::string strError;
                    strError = strprintf("Invalid parameter: flag %s", params[curparam].get_str());
                    throw JSONRPCError(RPC_INVALID_PARAMS, strError);
                }
            }

            // Now find a compatible authority
            std::vector<COutput> coins;
            int nOptions = wallet->FilterCoins(coins, [auth, grpID](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                if ((tg.associatedGroup == grpID) && tg.isAuthority() && tg.allowsRenew())
                {
                    // does this authority have at least the needed bits set?
                    if ((tg.controllingGroupFlags() & auth) == auth)
                        return true;
                }
                return false;
            });

            // if its a subgroup look for a parent authority that will work
            if ((nOptions == 0) && (grpID.isSubgroup()))
            {
                // if its a subgroup look for a parent authority that will work
                nOptions = wallet->FilterCoins(coins, [auth, grpID](const CWalletTx *tx, const CTxOut *out) {
                    CTokenGroupInfo tg(out->scriptPubKey);
                    if (tg.isAuthority() && tg.allowsRenew() && tg.allowsSubgroup() &&
                        (tg.associatedGroup == grpID.parentGroup()))
                    {
                        if ((tg.controllingGroupFlags() & auth) == auth)
                            return true;
                    }
                    return false;
                });
            }

            if (nOptions == 0) // TODO: look for multiple authorities that can be combined to form the required bits
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "No authority exists that can grant the requested priviledges.");
            }
            else
            {
                // Just pick the first compatible authority.
                for (auto coin : coins)
                {
                    totalBchAvailable += coin.tx->vout[coin.i].nValue;
                    chosenCoins.push_back(coin);
                    break;
                }
            }

            CReserveKey renewAuthorityKey(wallet);
            totalBchNeeded += RenewAuthority(chosenCoins[0], outputs, renewAuthorityKey);

            { // Construct the new authority
                CScript script = GetScriptForDestination(dst, grpID, (CAmount)auth);
                CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
                outputs.push_back(recipient);
                totalBchNeeded += GROUPED_SATOSHI_AMT;
            }

            CWalletTx wtx;
            ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, grpID, wallet);
            renewAuthorityKey.KeepKey();
            return wtx.GetHash().GetHex();
        }
    }
    else if (operation == "new")
    {
        LOCK2(cs_main, wallet->cs_wallet);

        unsigned int curparam = 1;

        // CCoinControl coinControl;
        // coinControl.fAllowOtherInputs = true; // Allow a normal bitcoin input for change
        COutput coin(nullptr, 0, 0, false);

        {
            std::vector<COutput> coins;
            CAmount lowest = Params().MaxMoneyOut();
            wallet->FilterCoins(coins, [&lowest](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                // although its possible to spend a grouped input to produce
                // a single mint group, I won't allow it to make the tx construction easier.
                if ((tg.associatedGroup == NoGroup) && (out->nValue < lowest))
                {
                    lowest = out->nValue;
                    return true;
                }
                return false;
            });

            if (0 == coins.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "No coins available in the wallet");
            }
            coin = coins[coins.size() - 1];
        }

        uint64_t grpNonce = 0;

        std::vector<COutput> chosenCoins;
        chosenCoins.push_back(coin);

        std::vector<CRecipient> outputs;

        CReserveKey authKeyReservation(wallet);
        CTxDestination authDest;
        CScript opretScript;
        if (curparam >= params.size())
        {
            CPubKey authKey;
            authKeyReservation.GetReservedKey(authKey);
            authDest = authKey.GetID();
        }
        else
        {
            authDest = DecodeDestination(params[curparam].get_str(), Params());
            if (authDest == CTxDestination(CNoDestination()))
            {
                auto desc = ParseGroupDescParams(params, curparam);
                if (desc.size()) // Add an op_return if there's a token desc doc
                {
                    opretScript = BuildTokenDescScript(desc);
                    outputs.push_back(CRecipient{opretScript, 0, false});
                }
                CPubKey authKey;
                authKeyReservation.GetReservedKey(authKey);
                authDest = authKey.GetID();
            }
        }
        curparam++;

        CTokenGroupID grpID = findGroupId(coin.GetOutPoint(), opretScript, TokenGroupIdFlags::NONE, grpNonce);

        CScript script = GetScriptForDestination(authDest, grpID, (CAmount)GroupAuthorityFlags::ALL | grpNonce);
        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
        outputs.push_back(recipient);

        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, coin.GetValue(), 0, 0, 0, grpID, wallet);
        authKeyReservation.KeepKey();
        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("groupIdentifier", EncodeTokenGroup(grpID)));
        ret.push_back(Pair("transaction", wtx.GetHash().GetHex()));
        return ret;
    }


    else if (operation == "mint")
    {
        LOCK(cs_main); // to maintain locking order
        LOCK(wallet->cs_wallet); // because I am reserving UTXOs for use in a tx
        CTokenGroupID grpID;
        CAmount totalTokensNeeded = 0;
        CAmount totalBchNeeded = GROUPED_SATOSHI_AMT; // for the mint destination output
        unsigned int curparam = 1;
        std::vector<CRecipient> outputs;
        // Get data from the parameter line. this fills grpId and adds 1 output for the correct # of tokens
        curparam = ParseGroupAddrValue(params, curparam, grpID, outputs, totalTokensNeeded, true);

        if (outputs.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "No destination address or payment amount");
        }
        if (curparam != params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Improper number of parameters, did you forget the payment amount?");
        }

        CCoinControl coinControl;
        coinControl.fAllowOtherInputs = true; // Allow a normal bitcoin input for change
        std::string strError;

        // Now find a mint authority
        std::vector<COutput> coins;
        int nOptions = wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
            CTokenGroupInfo tg(out->scriptPubKey);
            if ((tg.associatedGroup == grpID) && tg.allowsMint())
            {
                return true;
            }
            return false;
        });

        // if its a subgroup look for a parent authority that will work
        // As an idiot-proofing step, we only allow parent authorities that can be renewed, but that is a
        // preference coded in this wallet, not a group token requirement.
        if ((nOptions == 0) && (grpID.isSubgroup()))
        {
            // if its a subgroup look for a parent authority that will work
            nOptions = wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                if (tg.isAuthority() && tg.allowsRenew() && tg.allowsSubgroup() && tg.allowsMint() &&
                    (tg.associatedGroup == grpID.parentGroup()))
                {
                    return true;
                }
                return false;
            });
        }

        if (nOptions == 0)
        {
            strError = _("To mint coins, an authority output with mint capability is needed.");
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
        }
        CAmount totalBchAvailable = 0;
        COutput authority(nullptr, 0, 0, false);

        // Just pick the first one for now.
        for (auto coin : coins)
        {
            totalBchAvailable += coin.tx->vout[coin.i].nValue;
            authority = coin;
            break;
        }

        std::vector<COutput> chosenCoins;
        chosenCoins.push_back(authority);

        CReserveKey childAuthorityKey(wallet);
        totalBchNeeded += RenewAuthority(authority, outputs, childAuthorityKey);

        CWalletTx wtx;
        // I don't "need" tokens even though they are in the output because I'm minting, which is why
        // the token quantities are 0
        ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, grpID, wallet);
        childAuthorityKey.KeepKey();
        return wtx.GetHash().GetHex();
    }
    else if (operation == "balance")
    {
        if (params.size() > 3)
        {
            throw std::runtime_error("Invalid number of argument to token balance");
        }
        if (params.size() == 1) // no group specified, show them all
        {
            std::unordered_map<CTokenGroupID, CAmount> balances;
            GetAllGroupBalances(wallet, balances);
            UniValue ret(UniValue::VOBJ);
            for (const auto &item : balances)
            {
                ret.push_back(Pair(EncodeTokenGroup(item.first), tokenGroupManager->TokenValueFromAmount(item.second, item.first)));
            }
            return ret;
        }
        CTokenGroupID grpID = GetTokenGroup(params[1].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter 1: No group specified");
        }
        CTxDestination dst;
        if (params.size() > 2)
        {
            dst = DecodeDestination(params[2].get_str(), Params());
        }
        return UniValue(GetGroupBalance(grpID, dst, wallet));
    }
    else if (operation == "send")
    {
        CTokenGroupID grpID;
        CAmount totalTokensNeeded = 0;
        unsigned int curparam = 1;
        std::vector<CRecipient> outputs;
        curparam = ParseGroupAddrValue(params, curparam, grpID, outputs, totalTokensNeeded, true);

        if (outputs.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "No destination address or payment amount");
        }
        if (curparam != params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Improper number of parameters, did you forget the payment amount?");
        }
        CWalletTx wtx;
        GroupSend(wtx, grpID, outputs, totalTokensNeeded, wallet);
        return wtx.GetHash().GetHex();
    }
    else if (operation == "melt")
    {
        CTokenGroupID grpID;
        std::vector<CRecipient> outputs;

        grpID = GetTokenGroup(params[1].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }

        CAmount totalNeeded = tokenGroupManager->AmountFromTokenValue(params[2], grpID);

        CWalletTx wtx;
        GroupMelt(wtx, grpID, totalNeeded, wallet);
        return wtx.GetHash().GetHex();
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Unknown group operation");
    }
    return NullUniValue;
}

extern UniValue managementtoken(const UniValue &paramsIn, bool fHelp)
{
    CWallet *wallet = pwalletMain;
    if (!pwalletMain)
        return NullUniValue;

     if (fHelp || paramsIn.size() < 1)
        throw std::runtime_error(
            "token [new, mint, melt, send] \n"
            "\nToken functions.\n"
            "'new' creates a new token type. args: authorityAddress\n"
            "'mint' creates new tokens. args: groupId address quantity\n"
            "'melt' removes tokens from circulation. args: groupId quantity\n"
            "'balance' reports quantity of this token. args: groupId [address]\n"
            "'send' sends tokens to a new address. args: groupId address quantity [address quantity...]\n"
            "'authority create' creates a new authority args: groupId address [mint melt nochild rescript]\n"
            "'subgroup' translates a group and additional data into a subgroup identifier. args: groupId data\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) the destination address\n"
            "2. \"quantity\"    (numeric, required) the quantity desired\n"
            "3. \"data\"        (number, 0xhex, or string) binary data\n"
            "\nResult:\n"
            "\n"
            "\nExamples:\n"
            "\nCreate a transaction with no inputs\n" +
            HelpExampleCli("managementtoken", "new \"XDM\" \"DarkMatter\" \"https://github.com/ioncoincore/ion/desc.json\" 0") +
            "\nAdd sufficient unsigned inputs to meet the output value\n" +
            HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") + "\nSign the transaction\n" +
            HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") + "\nSend the transaction\n" +
            HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\""));

    std::string operation;
    std::string p0 = paramsIn[0].get_str();
    std::transform(p0.begin(), p0.end(), std::back_inserter(operation), ::tolower);
    EnsureWalletIsUnlocked();

    UniValue params(UniValue::VARR);
    params.push_back(paramsIn[0]);
    params.push_back("rtdarkmatter");
    for (unsigned int i=1; i < paramsIn.size(); i++)
    {
        params.push_back(paramsIn[i]);
    }

    if (operation == "new")
    {
        LOCK2(cs_main, wallet->cs_wallet);
        unsigned int curparam = 2;

        CReserveKey authKeyReservation(wallet);
        CTxDestination authDest;
        CScript opretScript;
        std::vector<CRecipient> outputs;

        if (curparam >= params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameters");        }
        else
        {
            authDest = DecodeDestination(params[curparam].get_str(), Params());
            if (authDest == CTxDestination(CNoDestination()))
            {
                auto desc = ParseGroupDescParams(params, curparam);
                if (desc.size()) // Add an op_return if there's a token desc doc
                {
                    opretScript = BuildTokenDescScript(desc);
                    outputs.push_back(CRecipient{opretScript, 0, false});
                }
                CPubKey authKey;
                authKeyReservation.GetReservedKey(authKey);
                authDest = authKey.GetID();
            }
        }
        curparam++;

        COutput coin(nullptr, 0, 0, false);
        CTxDestination dest = DecodeDestination(Params().TokenManagementKey());
        {
            std::vector<COutput> coins;
            CAmount lowest = Params().MaxMoneyOut();
            wallet->FilterCoins(coins, [&lowest, dest](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                // although its possible to spend a grouped input to produce
                // a single mint group, I won't allow it to make the tx construction easier.

                if ((tg.associatedGroup == NoGroup))
                {
                    CTxDestination address;
                    txnouttype whichType;
                    if (ExtractDestinationAndType(out->scriptPubKey, address, whichType))
                    {
                        if (address == dest){
                            if ((out->nValue < lowest))
                            {
                                lowest = out->nValue;
                                return true;
                            }
                        }
                    }
                }
                return false;
            });

            if (0 == coins.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Input tx is not available for spending");
            }

            coin = coins[coins.size() - 1];
        }
        if (coin.tx == nullptr)
            throw JSONRPCError(RPC_INVALID_PARAMS, "Management Group Token key is not available");

        uint64_t grpNonce = 0;
        CTokenGroupID grpID = findGroupId(coin.GetOutPoint(), opretScript, (TokenGroupIdFlags)TokenGroupIdFlags::STICKY_MELT | TokenGroupIdFlags::MGT_TOKEN, grpNonce);

        std::vector<COutput> chosenCoins;
        chosenCoins.push_back(coin);

        CScript script = GetScriptForDestination(authDest, grpID, (CAmount)GroupAuthorityFlags::ALL | grpNonce);
        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
        outputs.push_back(recipient);

        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, coin.GetValue(), 0, 0, 0, grpID, wallet);
        authKeyReservation.KeepKey();
        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("groupIdentifier", EncodeTokenGroup(grpID)));
        ret.push_back(Pair("transaction", wtx.GetHash().GetHex()));
        return ret;
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Unknown group operation");
    }
    return NullUniValue;
}

extern UniValue tokeninfo(const UniValue &params, bool fHelp)
{
    if (!pwalletMain)
        return NullUniValue;

    if (fHelp || params.size() < 1)
        throw std::runtime_error(
            "tokeninfo [list, stats] \n"
            "\nToken group description functions.\n"
            "'get' downloads the token group description json file. args: URL\n"
            "'checksum' generates the checksum of the token group description file. args: URL\n"
            "\nArguments:\n"
            "1. \"URL\"     (string, required) the URL of the token group description file\n" +
            HelpExampleCli("tokeninfo", "\"https://github.com/ioncoincore/ion/desc.json\""));

    std::string operation;
    std::string p0 = params[0].get_str();
    std::transform(p0.begin(), p0.end(), std::back_inserter(operation), ::tolower);

    std::string url;

    UniValue ret(UniValue::VARR);

    if (operation == "list") {
        unsigned int curparam = 1;

        if (curparam < params.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Too many parameters");
        }

        for (auto tokenGroupMapping : tokenGroupManager->GetMapTokenGroups()) {
            LogPrint("token", "%s - tokenGroupMapping has [%s] [%s]\n", __func__, tokenGroupMapping.second.tokenGroupDescription.strTicker, EncodeTokenGroup(tokenGroupMapping.second.tokenGroupInfo.associatedGroup));
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("groupIdentifier", EncodeTokenGroup(tokenGroupMapping.second.tokenGroupInfo.associatedGroup)));
            entry.push_back(Pair("txid", tokenGroupMapping.second.creationTransaction.GetHash().GetHex()));
            entry.push_back(Pair("ticker", tokenGroupMapping.second.tokenGroupDescription.strTicker));
            entry.push_back(Pair("name", tokenGroupMapping.second.tokenGroupDescription.strName));
            entry.push_back(Pair("decimalPos", tokenGroupMapping.second.tokenGroupDescription.decimalPos));
            entry.push_back(Pair("URL", tokenGroupMapping.second.tokenGroupDescription.strDocumentUrl));
            entry.push_back(Pair("documentHash", tokenGroupMapping.second.tokenGroupDescription.documentHash.ToString()));
            ret.push_back(entry);
        }

    } else if (operation == "stats") {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        CBlockIndex *pindex = NULL;

        unsigned int curparam = 1;

        if (params.size() > curparam) {
            uint256 blockId;

            blockId.SetHex(params[curparam].get_str());
            BlockMap::iterator it = mapBlockIndex.find(blockId);
            if (it != mapBlockIndex.end()) {
                pindex = it->second;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Block not found");
            }
        } else {
            pindex = chainActive[chainActive.Height()];
        }

        uint256 hash = pindex ? pindex->GetBlockHash() : uint256();
        uint64_t nXDMTransactions = pindex ? pindex->nChainXDMTransactions : 0;
        uint64_t nHeight = pindex ? pindex->nHeight : -1;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("height", nHeight));
        entry.push_back(Pair("blockhash", hash.GetHex()));
        entry.push_back(Pair("XDM_count", nXDMTransactions));
        ret.push_back(entry);

    } else {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Unknown operation");
    }
    return ret;
}

extern void WalletTxToJSON(const CWalletTx &wtx, UniValue &entry);
using namespace std;

static void MaybePushAddress(UniValue &entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest))
    {
        entry.push_back(Pair("address", EncodeDestination(dest)));
    }
}

static void AcentryToJSON(const CAccountingEntry &acentry, const string &strAccount, UniValue &ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", UniValue(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

void ListGroupedTransactions(const CTokenGroupID &grp,
    const CWalletTx &wtx,
    const string &strAccount,
    int nMinDepth,
    bool fLong,
    UniValue &ret,
    const isminefilter &filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;

    wtx.GetGroupAmounts(grp, listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH (const COutputEntry &s, listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwalletMain, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination);
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("group", EncodeTokenGroup(grp)));
            entry.push_back(Pair("amount", UniValue(-s.amount)));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name));
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        BOOST_FOREACH (const COutputEntry &r, listReceived)
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination))
                account = pwalletMain->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwalletMain, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                {
                    entry.push_back(Pair("category", "receive"));
                }
                entry.push_back(Pair("amount", UniValue(r.amount)));
                entry.push_back(Pair("group", EncodeTokenGroup(grp)));
                if (pwalletMain->mapAddressBook.count(r.destination))
                    entry.push_back(Pair("label", account));
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

UniValue groupedlisttransactions(const UniValue &params, bool fHelp)
{
    if (!pwalletMain)
        return NullUniValue;

    if (fHelp || params.size() > 6)
        throw runtime_error(
            "listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account "
            "'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see "
            "'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the "
            "transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"bitcoinaddress\",    (string) The bitcoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off "
            "blockchain)\n"
            "                                                transaction between accounts, and not associated with an "
            "address,\n"
            "                                                transaction id or block. 'send' and 'receive' "
            "transactions are \n"
            "                                                associated with an address, transaction id and block "
            "details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in ION."
            "This is negative for the 'send' category, and for the\n"
                            "                                         'move' category for moves outbound. It is "
                            "positive for the 'receive' category,\n"
                            "                                         and for the 'move' category for inbound funds.\n"
                            "    \"vout\": n,                (numeric) the vout value\n"
                            "    \"fee\": x.xxx,             (numeric) The amount of the fee in "
            "ION"
            ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for "
            "'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations "
            "indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction "
            "safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for "
            "'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. "
            "Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category "
            "of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 "
            "1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 "
            "GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\": \"label\"        (string) A comment for the address/transaction, if any\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the "
            "funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for "
            "sending funds,\n"
            "                                          negative amounts).\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are "
            "respendable). Only available for the \n"
            "                                         'send' category of transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n" +
            HelpExampleCli("listtransactions", "") + "\nList transactions 100 to 120\n" +
            HelpExampleCli("listtransactions", "\"*\" 20 100") + "\nAs a json rpc call\n" +
            HelpExampleRpc("listtransactions", "\"*\", 20, 100"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = "*";

    if (params.size() == 1)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    CTokenGroupID grpID = GetTokenGroup(params[1].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }

    if (params.size() > 2)
        strAccount = params[2].get_str();
    int nCount = 10;
    if (params.size() > 3)
        nCount = params[3].get_int();
    int nFrom = 0;
    if (params.size() > 4)
        nFrom = params[4].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if (params.size() > 5)
        if (params[5].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems &txOrdered = pwalletMain->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListGroupedTransactions(grpID, *pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount + nFrom))
            break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues();

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom + nCount);

    if (last != arrTmp.end())
        arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin())
        arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue groupedlistsinceblock(const UniValue &params, bool fHelp)
{
    if (!pwalletMain)
        return NullUniValue;

    if (fHelp)
        throw runtime_error(
            "token listsinceblock ( groupid \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. groupid (string, required) List transactions containing this group only\n"
            "2. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "3. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "4. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses "
            "(see 'importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the "
            "transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"bitcoinaddress\",    (string) The bitcoin address of the transaction. Not present for "
            "move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, "
            "'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in "
            "ION. This is negative for the 'send' category, and for the 'move' category for moves \n"
                            "                                          outbound. It is positive for the 'receive' "
                            "category, and for the 'move' category for inbound funds.\n"
                            "    \"vout\" : n,               (numeric) the vout value\n"
                            "    \"fee\": x.xxx,             (numeric) The amount of the fee in "
            "ION"
            ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for "
            "'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for "
            "'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. "
            "Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' "
            "category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). "
            "Available for 'send' and 'receive' category of transactions.\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are "
            "respendable). Only available for the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("listsinceblock", "") +
            HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6") +
            HelpExampleRpc(
                "listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (params.size() == 1)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    CTokenGroupID grpID = GetTokenGroup(params[1].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }

    if (params.size() > 2)
    {
        uint256 blockId;

        blockId.SetHex(params[2].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
            pindex = it->second;
    }

    if (params.size() > 3)
    {
        target_confirms = boost::lexical_cast<unsigned int>(params[3].get_str());

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if (params.size() > 4)
        if (InterpretBool(params[4].get_str()))
            filter = filter | ISMINE_WATCH_ONLY;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end();
         it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListGroupedTransactions(grpID, tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}
