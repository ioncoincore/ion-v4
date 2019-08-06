// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2019 The ION Core developers
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

    int32_t decimalPosition;
    if (!ParseInt32(params[curparam].get_str(), &decimalPosition) || decimalPosition > 16 || decimalPosition < 0) {
        std::string strError = strprintf("Parameter %d is invalid - valid values are between 0 and 16", decimalPosition);
        throw JSONRPCError(RPC_INVALID_PARAMS, strError);
    }
    ret.push_back(std::vector<unsigned char>({(unsigned char)decimalPosition}));
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
        EnsureWalletIsUnlocked();

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
    else if (operation == "createauthority")
    {
        EnsureWalletIsUnlocked();

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
        if (curparam < params.size()) // If flags are not specified, we assign all authorities
        {
            auth = ParseAuthorityParams(params, curparam);
            if (curparam < params.size())
            {
                std::string strError;
                strError = strprintf("Invalid parameter: flag %s", params[curparam].get_str());
                throw JSONRPCError(RPC_INVALID_PARAMS, strError);
            }
        } else {
            auth = GroupAuthorityFlags::ALL;
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
        ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, 0, 0, grpID, wallet);
        renewAuthorityKey.KeepKey();
        return wtx.GetHash().GetHex();
    }
    else if (operation == "dropauthorities")
    {
        // Parameters:
        // - tokenGroupID
        // - tx ID of UTXU that needs to drop authorities
        // - vout value of UTXU that needs to drop authorities
        // - authority to remove
        // This function removes authority for a tokengroupID at a specific UTXO
        EnsureWalletIsUnlocked();

        LOCK2(cs_main, wallet->cs_wallet);
        CAmount totalBchNeeded = 0;
        CAmount totalBchAvailable = 0;
        unsigned int curparam = 1;
        std::vector<COutput> availableCoins;
        std::vector<COutput> chosenCoins;
        std::vector<CRecipient> outputs;
        if (curparam >= params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameters");
        }

        CTokenGroupID grpID;
        // Get the group id from the command line
        grpID = GetTokenGroup(params[curparam].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }

        // Get the txid/voutnr from the command line
        curparam++;
        uint256 txid;
        txid.SetHex(params[curparam].get_str());
        // Note: IsHex("") is false
        if (txid == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: wrong txid");
        }

        curparam++;
        int32_t voutN;
        if (!ParseInt32(params[curparam].get_str(), &voutN) || voutN < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: wrong vout nr");
        }

        wallet->AvailableCoins(availableCoins, true, NULL, false, ALL_COINS, false, 1, true);
        if (availableCoins.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: provided output is not available");
        }

        for (auto coin : availableCoins) {
            if (coin.tx->GetHash() == txid && coin.i == voutN) {
                chosenCoins.push_back(coin);
            }
        }
        if (chosenCoins.size() == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: provided output is not available");
        }

        // Get what authority permissions the user wants from the command line
        curparam++;
        GroupAuthorityFlags authoritiesToDrop = GroupAuthorityFlags::NONE;
        if (curparam < params.size()) // If flags are not specified, we assign all authorities
        {
            while (1)
            {
                std::string sflag;
                std::string p = params[curparam].get_str();
                std::transform(p.begin(), p.end(), std::back_inserter(sflag), ::tolower);
                if (sflag == "mint")
                    authoritiesToDrop |= GroupAuthorityFlags::MINT;
                else if (sflag == "melt")
                    authoritiesToDrop |= GroupAuthorityFlags::MELT;
                else if (sflag == "child")
                    authoritiesToDrop |= GroupAuthorityFlags::CCHILD;
                else if (sflag == "rescript")
                    authoritiesToDrop |= GroupAuthorityFlags::RESCRIPT;
                else if (sflag == "subgroup")
                    authoritiesToDrop |= GroupAuthorityFlags::SUBGROUP;
                else if (sflag == "all")
                    authoritiesToDrop |= GroupAuthorityFlags::ALL;
                else
                    break; // If param didn't match, then return because we've left the list of flags
                curparam++;
                if (curparam >= params.size())
                    break;
            }
            if (curparam < params.size())
            {
                std::string strError;
                strError = strprintf("Invalid parameter: flag %s", params[curparam].get_str());
                throw JSONRPCError(RPC_INVALID_PARAMS, strError);
            }
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: need to specify which capabilities to drop");
        }

        CScript script = chosenCoins.at(0).GetScriptPubKey();
        CTokenGroupInfo tgInfo(script);
        CTxDestination dest;
        ExtractDestination(script, dest);
        string strAuthorities = EncodeGroupAuthority(tgInfo.controllingGroupFlags());

        GroupAuthorityFlags authoritiesToKeep = tgInfo.controllingGroupFlags() & ~authoritiesToDrop;

        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("groupIdentifier", EncodeTokenGroup(tgInfo.associatedGroup)));
        ret.push_back(Pair("transaction", txid.GetHex()));
        ret.push_back(Pair("vout", voutN));
        ret.push_back(Pair("coin", chosenCoins.at(0).ToString()));
        ret.push_back(Pair("script", script.ToString()));
        ret.push_back(Pair("destination", EncodeDestination(dest)));
        ret.push_back(Pair("authorities_former", strAuthorities));
        ret.push_back(Pair("authorities_new", EncodeGroupAuthority(authoritiesToKeep)));

        if ((authoritiesToKeep == GroupAuthorityFlags::CTRL) || (authoritiesToKeep == GroupAuthorityFlags::NONE) || !hasCapability(authoritiesToKeep, GroupAuthorityFlags::CTRL)) {
            ret.push_back(Pair("status", "Dropping all authorities"));
        } else {
            // Construct the new authority
            CScript script = GetScriptForDestination(dest, grpID, (CAmount)authoritiesToKeep);
            CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
            outputs.push_back(recipient);
            totalBchNeeded += GROUPED_SATOSHI_AMT;
        }
        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, 0, 0, grpID, wallet);
        return ret;
    }
    else if (operation == "new")
    {
        EnsureWalletIsUnlocked();

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

        std::string strError;
        std::vector<COutput> coins;

        // When minting a regular (non-management) token, an XDM fee is needed
        // Note that XDM itself is also a management token
        // Add XDM output to fee address and to change address
        CAmount XDMFeeNeeded = 0;
        CAmount totalXDMAvailable = 0;
        if (!grpID.hasFlag(TokenGroupIdFlags::MGT_TOKEN))
        {
            tokenGroupManager->GetXDMFee(chainActive.Tip(), XDMFeeNeeded);
            XDMFeeNeeded *= 5;

            // Ensure enough XDM fees are paid
            tokenGroupManager->EnsureXDMFee(outputs, XDMFeeNeeded);

            // Add XDM inputs
            if (XDMFeeNeeded > 0) {
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
            }

            if (totalXDMAvailable < XDMFeeNeeded)
            {
                strError = strprintf("Not enough XDM in the wallet.  Need %d more.", tokenGroupManager->TokenValueFromAmount(XDMFeeNeeded - totalXDMAvailable, grpID));
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
            }

            // Get a near but greater quantity
            totalXDMAvailable = GroupCoinSelection(coins, XDMFeeNeeded, chosenCoins);
        }

        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, coin.GetValue(), 0, 0, 0, totalXDMAvailable, XDMFeeNeeded, grpID, wallet);
        authKeyReservation.KeepKey();
        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("groupIdentifier", EncodeTokenGroup(grpID)));
        ret.push_back(Pair("transaction", wtx.GetHash().GetHex()));
        return ret;
    }
    else if (operation == "checknew")
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

        std::string strError;
        std::vector<COutput> coins;

        // When minting a regular (non-management) token, an XDM fee is needed
        // Note that XDM itself is also a management token
        // Add XDM output to fee address and to change address
        CAmount XDMFeeNeeded = 0;
        CAmount totalXDMAvailable = 0;
        if (!grpID.hasFlag(TokenGroupIdFlags::MGT_TOKEN))
        {
            tokenGroupManager->GetXDMFee(chainActive.Tip(), XDMFeeNeeded);
            XDMFeeNeeded *= 5;

            // Ensure enough XDM fees are paid
            tokenGroupManager->EnsureXDMFee(outputs, XDMFeeNeeded);

            // Add XDM inputs
            if (XDMFeeNeeded > 0) {
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
            }

            if (totalXDMAvailable < XDMFeeNeeded)
            {
                strError = strprintf("Not enough XDM in the wallet.  Need %d more.", tokenGroupManager->TokenValueFromAmount(XDMFeeNeeded - totalXDMAvailable, grpID));
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
            }

            // Get a near but greater quantity
            totalXDMAvailable = GroupCoinSelection(coins, XDMFeeNeeded, chosenCoins);
        }

        UniValue ret(UniValue::VOBJ);

        UniValue retChosenCoins(UniValue::VARR);
        for (auto coin : chosenCoins) {
            retChosenCoins.push_back(coin.ToString());
        }
        ret.push_back(Pair("chosen_coins", retChosenCoins));
        UniValue retOutputs(UniValue::VOBJ);
        for (auto output : outputs) {
            retOutputs.push_back(Pair(output.scriptPubKey.ToString(), output.nAmount));
        }
        ret.push_back(Pair("outputs", retOutputs));

        if (tokenGroupManager->ManagementTokensCreated()) {
            ret.push_back(Pair("xdm_available", tokenGroupManager->TokenValueFromAmount(totalXDMAvailable, tokenGroupManager->GetDarkMatterID())));
            ret.push_back(Pair("xdm_needed", tokenGroupManager->TokenValueFromAmount(XDMFeeNeeded, tokenGroupManager->GetDarkMatterID())));
        }
        ret.push_back(Pair("group_identifier", EncodeTokenGroup(grpID)));

        CTokenGroupInfo tokenGroupInfo(opretScript);
        CTokenGroupDescription tokenGroupDescription(opretScript);
        CTokenGroupStatus tokenGroupStatus;
        CTransaction dummyTransaction;
        CTokenGroupCreation tokenGroupCreation(dummyTransaction, tokenGroupInfo, tokenGroupDescription, tokenGroupStatus);
        tokenGroupCreation.ValidateDescription();

        ret.push_back(Pair("token_group_description_ticker", tokenGroupCreation.tokenGroupDescription.strTicker));
        ret.push_back(Pair("token_group_description_name", tokenGroupCreation.tokenGroupDescription.strName));
        ret.push_back(Pair("token_group_description_decimalpos", tokenGroupCreation.tokenGroupDescription.nDecimalPos));
        ret.push_back(Pair("token_group_description_documenturl", tokenGroupCreation.tokenGroupDescription.strDocumentUrl));
        ret.push_back(Pair("token_group_description_documenthash", tokenGroupCreation.tokenGroupDescription.documentHash.ToString()));
        ret.push_back(Pair("token_group_status", tokenGroupCreation.status.messages));

        return ret;
    }
    else if (operation == "mint")
    {
        EnsureWalletIsUnlocked();

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

        // When minting a regular (non-management) token, an XDM fee is needed
        // Note that XDM itself is also a management token
        // Add XDM output to fee address and to change address
        CAmount XDMFeeNeeded = 0;
        CAmount totalXDMAvailable = 0;
        if (!grpID.hasFlag(TokenGroupIdFlags::MGT_TOKEN))
        {
            tokenGroupManager->GetXDMFee(chainActive.Tip(), XDMFeeNeeded);
            XDMFeeNeeded *= 5;

            // Ensure enough XDM fees are paid
            tokenGroupManager->EnsureXDMFee(outputs, XDMFeeNeeded);

            // Add XDM inputs
            if (XDMFeeNeeded > 0) {
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
            }

            if (totalXDMAvailable < XDMFeeNeeded)
            {
                strError = strprintf("Not enough XDM in the wallet.  Need %d more.", tokenGroupManager->TokenValueFromAmount(XDMFeeNeeded - totalXDMAvailable, grpID));
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
            }

            // Get a near but greater quantity
            totalXDMAvailable = GroupCoinSelection(coins, XDMFeeNeeded, chosenCoins);
        }

        // I don't "need" tokens even though they are in the output because I'm minting, which is why
        // the token quantities are 0
        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, totalXDMAvailable, XDMFeeNeeded, grpID, wallet);
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
            std::unordered_map<CTokenGroupID, GroupAuthorityFlags> authorities;
            GetAllGroupBalancesAndAuthorities(wallet, balances, authorities);
            UniValue ret(UniValue::VARR);
            for (const auto &item : balances)
            {
                CTokenGroupID grpID = item.first;
                UniValue retobj(UniValue::VOBJ);
                retobj.push_back(Pair("groupIdentifier", EncodeTokenGroup(grpID)));

                CTokenGroupCreation tgCreation;
                if (grpID.isSubgroup()) {
                    CTokenGroupID parentgrp = grpID.parentGroup();
                    std::vector<unsigned char> subgroupData = grpID.GetSubGroupData();
                    tokenGroupManager->GetTokenGroupCreation(grpID, tgCreation);
                    retobj.push_back(Pair("parentGroupIdentifier", EncodeTokenGroup(parentgrp)));
                    retobj.push_back(Pair("subgroup-data", std::string(subgroupData.begin(), subgroupData.end())));
                } else {
                    tokenGroupManager->GetTokenGroupCreation(grpID, tgCreation);
                }
                retobj.push_back(Pair("ticker", tgCreation.tokenGroupDescription.strTicker));
                retobj.push_back(Pair("name", tgCreation.tokenGroupDescription.strName));

                retobj.push_back(Pair("balance", tokenGroupManager->TokenValueFromAmount(item.second, item.first)));
                if (hasCapability(authorities[item.first], GroupAuthorityFlags::CTRL)) 
                    retobj.push_back(Pair("authorities", EncodeGroupAuthority(authorities[item.first])));

                ret.push_back(retobj);
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
        CAmount balance;
        GroupAuthorityFlags authorities;
        GetGroupBalanceAndAuthorities(balance, authorities, grpID, dst, wallet);
        UniValue retobj(UniValue::VOBJ);
        retobj.push_back(Pair("groupIdentifier", EncodeTokenGroup(grpID)));
        retobj.push_back(Pair("balance", tokenGroupManager->TokenValueFromAmount(balance, grpID)));
        if (hasCapability(authorities, GroupAuthorityFlags::CTRL)) 
            retobj.push_back(Pair("authorities", EncodeGroupAuthority(authorities)));
        return retobj;
    }
    else if (operation == "listauthorities")
    {
        if (params.size() > 2)
        {
            throw std::runtime_error("Invalid number of argument to token authorities");
        }
        std::vector<COutput> coins;
        if (params.size() == 1) // no group specified, show them all
        {
            ListAllGroupAuthorities(wallet, coins);
        } else {
            CTokenGroupID grpID = GetTokenGroup(params[1].get_str());
            if (!grpID.isUserGroup())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter 1: No group specified");
            }
            ListGroupAuthorities(wallet, coins, grpID);
        }
        UniValue ret(UniValue::VARR);
        for (const COutput &coin : coins)
        {
            CTokenGroupInfo tgInfo(coin.GetScriptPubKey());
            CTxDestination dest;
            ExtractDestination(coin.GetScriptPubKey(), dest);

            UniValue retobj(UniValue::VOBJ);
            retobj.push_back(Pair("groupIdentifier", EncodeTokenGroup(tgInfo.associatedGroup)));
            retobj.push_back(Pair("txid", coin.tx->GetHash().ToString()));
            retobj.push_back(Pair("vout", coin.i));
            retobj.push_back(Pair("address", EncodeDestination(dest)));
            retobj.push_back(Pair("token_authorities", EncodeGroupAuthority(tgInfo.controllingGroupFlags())));
            ret.push_back(retobj);
        }
        return ret;
    }
    else if (operation == "send")
    {
        EnsureWalletIsUnlocked();

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

        // Optionally, add XDM fee
        CAmount XDMFeeNeeded = 0;
        if (tokenGroupManager->MatchesDarkMatter(grpID)) {
            tokenGroupManager->GetXDMFee(chainActive.Tip(), XDMFeeNeeded);
        }

        // Ensure enough XDM fees are paid
        tokenGroupManager->EnsureXDMFee(outputs, XDMFeeNeeded);

        CWalletTx wtx;
        GroupSend(wtx, grpID, outputs, totalTokensNeeded, XDMFeeNeeded, wallet);
        return wtx.GetHash().GetHex();
    }
    else if (operation == "melt")
    {
        EnsureWalletIsUnlocked();

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
        // If the MagicToken exists: spend a magic token output
        // Otherwise: spend an ION output from the token management address
        if (tokenGroupManager->MagicTokensCreated()){
            CTokenGroupID magicID = tokenGroupManager->GetMagicID();

            std::vector<COutput> coins;
            CAmount lowest = Params().MaxMoneyOut();
            wallet->FilterCoins(coins, [&lowest, magicID](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupInfo tg(out->scriptPubKey);
                // although its possible to spend a grouped input to produce
                // a single mint group, I won't allow it to make the tx construction easier.

                if (tg.associatedGroup == magicID && !tg.isAuthority())
                {
                    CTxDestination address;
                    if (ExtractDestination(out->scriptPubKey, address)) {
                        if ((tg.quantity < lowest))
                        {
                            lowest = tg.quantity;
                            return true;
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

            // Add magic change
            CTxDestination address;
            ExtractDestination(coin.GetScriptPubKey(), address);
            CTokenGroupInfo tgMagicInfo(coin.GetScriptPubKey());
            CScript script = GetScriptForDestination(address, magicID, tgMagicInfo.getAmount());
            CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
            outputs.push_back(recipient);
        } else {
            CTxDestination dest = DecodeDestination(Params().TokenManagementKey());

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
        CTokenGroupID grpID = findGroupId(coin.GetOutPoint(), opretScript, TokenGroupIdFlags::MGT_TOKEN, grpNonce);

        std::vector<COutput> chosenCoins;
        chosenCoins.push_back(coin);

        CScript script = GetScriptForDestination(authDest, grpID, (CAmount)GroupAuthorityFlags::ALL | grpNonce);
        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
        outputs.push_back(recipient);

        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, coin.GetValue(), 0, 0, 0, 0, 0, grpID, wallet);
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

    if (operation == "all") {
        unsigned int curparam = 1;
        if (curparam < params.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Too many parameters");
        }

        for (auto tokenGroupMapping : tokenGroupManager->GetMapTokenGroups()) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("groupIdentifier", EncodeTokenGroup(tokenGroupMapping.second.tokenGroupInfo.associatedGroup)));
            entry.push_back(Pair("txid", tokenGroupMapping.second.creationTransaction.GetHash().GetHex()));
            entry.push_back(Pair("ticker", tokenGroupMapping.second.tokenGroupDescription.strTicker));
            entry.push_back(Pair("name", tokenGroupMapping.second.tokenGroupDescription.strName));
            entry.push_back(Pair("decimalPos", tokenGroupMapping.second.tokenGroupDescription.nDecimalPos));
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
        uint64_t nXDMSupply = pindex ? pindex->nXDMSupply : 0;
        uint64_t nMagicTransactions = pindex ? pindex->nChainMagicTransactions : 0;
        uint64_t nMagicSupply = pindex ? pindex->nMagicSupply : 0;
        uint64_t nHeight = pindex ? pindex->nHeight : -1;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("height", nHeight));
        entry.push_back(Pair("blockhash", hash.GetHex()));


        if (tokenGroupManager->DarkMatterTokensCreated()) {
            entry.push_back(Pair("XDM_supply", tokenGroupManager->TokenValueFromAmount(nXDMSupply, tokenGroupManager->GetDarkMatterID())));
            entry.push_back(Pair("XDM_transactions", (uint64_t)nXDMTransactions));
        }
        if (tokenGroupManager->MagicTokensCreated()) {
            entry.push_back(Pair("Magic_supply", tokenGroupManager->TokenValueFromAmount(nMagicSupply, tokenGroupManager->GetMagicID())));
            entry.push_back(Pair("Magic_transactions", (uint64_t)nMagicTransactions));
        }
        ret.push_back(entry);

    } else if (operation == "groupid") {
        unsigned int curparam = 1;
        if (params.size() > 2) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Too many parameters");
        }

        CTokenGroupID grpID;
        // Get the group id from the command line
        grpID = GetTokenGroup(params[curparam].get_str());
        if (!grpID.isUserGroup()) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("groupIdentifier", EncodeTokenGroup(grpID)));
        CTokenGroupCreation tgCreation;
        if (grpID.isSubgroup()) {
            CTokenGroupID parentgrp = grpID.parentGroup();
            std::vector<unsigned char> subgroupData = grpID.GetSubGroupData();
            tokenGroupManager->GetTokenGroupCreation(grpID, tgCreation);
            entry.push_back(Pair("parentGroupIdentifier", EncodeTokenGroup(parentgrp)));
            entry.push_back(Pair("subgroup-data", std::string(subgroupData.begin(), subgroupData.end())));
        } else {
            tokenGroupManager->GetTokenGroupCreation(grpID, tgCreation);
        }
        entry.push_back(Pair("txid", tgCreation.creationTransaction.GetHash().GetHex()));
        entry.push_back(Pair("ticker", tgCreation.tokenGroupDescription.strTicker));
        entry.push_back(Pair("name", tgCreation.tokenGroupDescription.strName));
        entry.push_back(Pair("decimalPos", tgCreation.tokenGroupDescription.nDecimalPos));
        entry.push_back(Pair("URL", tgCreation.tokenGroupDescription.strDocumentUrl));
        entry.push_back(Pair("documentHash", tgCreation.tokenGroupDescription.documentHash.ToString()));
        entry.push_back(Pair("status", tgCreation.status.messages));
        ret.push_back(entry);
    } else if (operation == "ticker") {
        unsigned int curparam = 1;
        if (params.size() > 2) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Too many parameters");
        }

        std::string ticker;
        CTokenGroupID grpID;
        tokenGroupManager->GetTokenGroupIdByTicker(params[curparam].get_str(), grpID);
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: could not find token group");
        }

        CTokenGroupCreation tgCreation;
        tokenGroupManager->GetTokenGroupCreation(grpID, tgCreation);

        LogPrint("token", "%s - tokenGroupCreation has [%s] [%s]\n", __func__, tgCreation.tokenGroupDescription.strTicker, EncodeTokenGroup(tgCreation.tokenGroupInfo.associatedGroup));
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("groupIdentifier", EncodeTokenGroup(tgCreation.tokenGroupInfo.associatedGroup)));
        entry.push_back(Pair("txid", tgCreation.creationTransaction.GetHash().GetHex()));
        entry.push_back(Pair("ticker", tgCreation.tokenGroupDescription.strTicker));
        entry.push_back(Pair("name", tgCreation.tokenGroupDescription.strName));
        entry.push_back(Pair("decimalPos", tgCreation.tokenGroupDescription.nDecimalPos));
        entry.push_back(Pair("URL", tgCreation.tokenGroupDescription.strDocumentUrl));
        entry.push_back(Pair("documentHash", tgCreation.tokenGroupDescription.documentHash.ToString()));
        entry.push_back(Pair("status", tgCreation.status.messages));
        ret.push_back(entry);
    } else if (operation == "name") {
        unsigned int curparam = 1;
        if (params.size() > 2) {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Too many parameters");
        }

        std::string name;
        CTokenGroupID grpID;
        tokenGroupManager->GetTokenGroupIdByName(params[curparam].get_str(), grpID);
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: Could not find token group");
        }

        CTokenGroupCreation tgCreation;
        tokenGroupManager->GetTokenGroupCreation(grpID, tgCreation);

        LogPrint("token", "%s - tokenGroupCreation has [%s] [%s]\n", __func__, tgCreation.tokenGroupDescription.strTicker, EncodeTokenGroup(tgCreation.tokenGroupInfo.associatedGroup));
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("groupIdentifier", EncodeTokenGroup(tgCreation.tokenGroupInfo.associatedGroup)));
        entry.push_back(Pair("txid", tgCreation.creationTransaction.GetHash().GetHex()));
        entry.push_back(Pair("ticker", tgCreation.tokenGroupDescription.strTicker));
        entry.push_back(Pair("name", tgCreation.tokenGroupDescription.strName));
        entry.push_back(Pair("decimalPos", tgCreation.tokenGroupDescription.nDecimalPos));
        entry.push_back(Pair("URL", tgCreation.tokenGroupDescription.strDocumentUrl));
        entry.push_back(Pair("documentHash", tgCreation.tokenGroupDescription.documentHash.ToString()));
        entry.push_back(Pair("status", tgCreation.status.messages));
        ret.push_back(entry);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: unknown operation");
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
