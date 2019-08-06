// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "tokens/tokengroupwallet.h"
#include "base58.h"
#include "ionaddrenc.h"
#include "coincontrol.h"
#include "coins.h"
#include "consensus/tokengroups.h"
#include "consensus/validation.h"
#include "core_io.h"
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
#include "tokens/tokengroupmanager.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include <algorithm>

#include <boost/lexical_cast.hpp>

// allow this many times fee overpayment, rather than make a change output
#define FEE_FUDGE 2

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

void GetAllGroupBalancesAndAuthorities(const CWallet *wallet, std::unordered_map<CTokenGroupID, CAmount> &balances, std::unordered_map<CTokenGroupID, GroupAuthorityFlags> &authorities)
{
    std::vector<COutput> coins;
    wallet->FilterCoins(coins, [&balances, &authorities](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if ((tg.associatedGroup != NoGroup)) {
            authorities[tg.associatedGroup] |= tg.controllingGroupFlags();
            if (!tg.isAuthority()) {
                if (tg.quantity > std::numeric_limits<CAmount>::max() - balances[tg.associatedGroup])
                    balances[tg.associatedGroup] = std::numeric_limits<CAmount>::max();
                else
                    balances[tg.associatedGroup] += tg.quantity;
            } else {
                balances[tg.associatedGroup] += 0;
            }
        }
        return false; // I don't want to actually filter anything
    });
}

void ListAllGroupAuthorities(const CWallet *wallet, std::vector<COutput> &coins) {
    wallet->FilterCoins(coins, [](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if (tg.isAuthority()) {
            return true;
        } else {
            return false;
        }
    });
}

void ListGroupAuthorities(const CWallet *wallet, std::vector<COutput> &coins, const CTokenGroupID &grpID) {
    wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if (tg.isAuthority() && tg.associatedGroup == grpID) {
            return true;
        } else {
            return false;
        }
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

void GetGroupBalanceAndAuthorities(CAmount &balance, GroupAuthorityFlags &authorities, const CTokenGroupID &grpID, const CTxDestination &dest, const CWallet *wallet)
{
    std::vector<COutput> coins;
    balance = 0;
    authorities = GroupAuthorityFlags::NONE;
    wallet->FilterCoins(coins, [grpID, dest, &balance, &authorities](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupInfo tg(out->scriptPubKey);
        if ((grpID == tg.associatedGroup)) // must be sitting in group address
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
                authorities |= tg.controllingGroupFlags();
                if (!tg.isAuthority()) {
                    if (tg.quantity > std::numeric_limits<CAmount>::max() - balance)
                        balance = std::numeric_limits<CAmount>::max();
                    else
                        balance += tg.quantity;
                } else {
                    balance += 0;
                }
            }
        }
        return false;
    });
}

CScript GetScriptForDestination(const CTxDestination &dest, const CTokenGroupID &group, const CAmount &amount)
{
    CScript script;

    boost::apply_visitor(CGroupScriptVisitor(group, amount, &script), dest);
    return script;
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

void ConstructTx(CWalletTx &wtxNew, const std::vector<COutput> &chosenCoins, const std::vector<CRecipient> &outputs,
    CAmount totalAvailable, CAmount totalNeeded, CAmount totalGroupedAvailable, CAmount totalGroupedNeeded,
    CAmount totalXDMAvailable, CAmount totalXDMNeeded, CTokenGroupID grpID, CWallet *wallet)
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

        if (totalXDMAvailable > totalXDMNeeded) // need to make a group change output
        {
            CPubKey newKey;

            if (!groupChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(GROUPED_SATOSHI_AMT,
                GetScriptForDestination(newKey.GetID(), tokenGroupManager->GetDarkMatterID(), totalXDMAvailable - totalXDMNeeded));
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
                strError = strprintf("Not enough funds for fee of %d ION.", FormatMoney(fee));
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

    for (auto vout : wtxNew.vout) {
        CTokenGroupInfo tgInfo(vout.scriptPubKey);
        if (!tgInfo.isInvalid()) {
            CTokenGroupCreation tgCreation;
            tokenGroupManager->GetTokenGroupCreation(tgInfo.associatedGroup, tgCreation);
            LogPrint("token", "%s - name[%s] amount[%d]\n", __func__, tgCreation.tokenGroupDescription.strName, tgInfo.quantity);
        }
    }

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
        strError = strprintf("Not enough tokens in the wallet.  Need %d more.", tokenGroupManager->TokenValueFromAmount(totalNeeded - totalAvailable, grpID));
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    chosenCoins.push_back(authority);

    CReserveKey childAuthorityKey(wallet);
    totalBchNeeded += RenewAuthority(authority, outputs, childAuthorityKey);
    // by passing a fewer tokens available than are actually in the inputs, there is a surplus.
    // This surplus will be melted.
    ConstructTx(wtxNew, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, totalAvailable - totalNeeded, 0, 0, 0, grpID,
        wallet);
    childAuthorityKey.KeepKey();
}

void GroupSend(CWalletTx &wtxNew,
    const CTokenGroupID &grpID,
    const std::vector<CRecipient> &outputs,
    CAmount totalNeeded,
    CAmount totalXDMNeeded,
    CWallet *wallet)
{
    LOCK2(cs_main, wallet->cs_wallet);
    std::string strError;
    std::vector<COutput> coins;
    std::vector<COutput> chosenCoins;

    // Add XDM inputs
    // Increase tokens needed when sending XDM and select XDM coins otherwise
    CAmount totalXDMAvailable = 0;
    if (tokenGroupManager->MatchesDarkMatter(grpID)) {
        totalNeeded += totalXDMNeeded;
        totalXDMNeeded = 0;
    } else {
        if (totalXDMNeeded > 0) {
            CTokenGroupID XDMGrpID = tokenGroupManager->GetDarkMatterID();
            wallet->FilterCoins(coins, [XDMGrpID, &totalXDMAvailable](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                if ((XDMGrpID == tg.associatedGroup) && !tg.isAuthority())
                {
                    totalXDMAvailable += tg.quantity;
                    return true;
                }
                return false;
            });

            if (totalXDMAvailable < totalXDMNeeded)
            {
                strError = strprintf("Not enough XDM in the wallet.  Need %d more.", tokenGroupManager->TokenValueFromAmount(totalXDMNeeded - totalXDMAvailable, grpID));
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
            }

            // Get a near but greater quantity
            totalXDMAvailable = GroupCoinSelection(coins, totalXDMNeeded, chosenCoins);
        }
    }

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
        strError = strprintf("Not enough tokens in the wallet.  Need %d more.", tokenGroupManager->TokenValueFromAmount(totalNeeded - totalAvailable, grpID));
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    // Get a near but greater quantity
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    // Display outputs
    for (auto output : outputs) {
        CTokenGroupInfo tgInfo(output.scriptPubKey);
        if (!tgInfo.isInvalid()) {
            CTokenGroupCreation tgCreation;
            tokenGroupManager->GetTokenGroupCreation(tgInfo.associatedGroup, tgCreation);
            LogPrint("token", "%s - name[%s] amount[%d]\n", __func__, tgCreation.tokenGroupDescription.strName, tgInfo.quantity);
        }
    }

    ConstructTx(wtxNew, chosenCoins, outputs, 0, GROUPED_SATOSHI_AMT * outputs.size(), totalAvailable, totalNeeded,
        totalXDMAvailable, totalXDMNeeded, grpID, wallet);
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
