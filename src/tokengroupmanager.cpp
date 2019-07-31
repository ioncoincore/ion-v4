// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokengroupmanager.h"
#include "wallet/tokengroupwallet.h"

#include "dstencode.h"
#include "rpc/protocol.h"
#include "utilstrencodings.h"
#include "tokengroupconfiguration.h"

std::shared_ptr<CTokenGroupManager> tokenGroupManager;

CTokenGroupManager::CTokenGroupManager() {
    vTokenGroupFilters.emplace_back(TGFilterCharacters);
    vTokenGroupFilters.emplace_back(TGFilterUniqueness);
    vTokenGroupFilters.emplace_back(TGFilterUpperCaseTicker);
}

bool CTokenGroupManager::StoreManagementTokenGroups(CTokenGroupCreation tokenGroupCreation) {
    if (!tgMagicCreation && tokenGroupCreation.tokenGroupDescription.strTicker == "MAGIC") {
        this->tgMagicCreation = std::unique_ptr<CTokenGroupCreation>(new CTokenGroupCreation((tokenGroupCreation)));
        return true;
    } else if (!tgDarkMatterCreation && tokenGroupCreation.tokenGroupDescription.strTicker == "XDM") {
        this->tgDarkMatterCreation = std::unique_ptr<CTokenGroupCreation>(new CTokenGroupCreation((tokenGroupCreation)));
        return true;
    } else if (!tgAtomCreation && tokenGroupCreation.tokenGroupDescription.strTicker == "ATOM") {
        this->tgAtomCreation = std::unique_ptr<CTokenGroupCreation>(new CTokenGroupCreation((tokenGroupCreation)));
        return true;
    }
    return false;
}

void CTokenGroupManager::ClearManagementTokenGroups() {
    tgMagicCreation.reset();
    tgDarkMatterCreation.reset();
    tgAtomCreation.reset();
}

bool CTokenGroupManager::MatchesMagic(CTokenGroupID tgID) {
    if (!tgMagicCreation) return false;
    return tgID == tgMagicCreation->tokenGroupInfo.associatedGroup;
}

bool CTokenGroupManager::MatchesDarkMatter(CTokenGroupID tgID) {
    if (!tgDarkMatterCreation) return false;
    return tgID == tgDarkMatterCreation->tokenGroupInfo.associatedGroup;
}

bool CTokenGroupManager::MatchesAtom(CTokenGroupID tgID) {
    if (!tgAtomCreation) return false;
    return tgID == tgAtomCreation->tokenGroupInfo.associatedGroup;
}

bool CTokenGroupManager::MagicTokensCreated() {
    return tgMagicCreation ? true : false;
};

bool CTokenGroupManager::DarkMatterTokensCreated() {
    return tgDarkMatterCreation ? true : false;
};

bool CTokenGroupManager::AtomTokensCreated() {
    return tgAtomCreation ? true : false;
};

bool CTokenGroupManager::IsManagementTokenInput(CScript script) {
    // Initially, the TokenManagementKey enables management token operations
    // When the MagicToken is created, the MagicToken enables management token operations
    if (!tgMagicCreation) {
        CTxDestination payeeDest;
        ExtractDestination(script, payeeDest);
        return EncodeDestination(payeeDest) == Params().TokenManagementKey();
    } else {
        CTokenGroupInfo grp(script);
        return MatchesMagic(grp.associatedGroup);
    }
}

bool CTokenGroupManager::AddTokenGroups(const std::vector<CTokenGroupCreation>& newTokenGroups) {
    for (auto tokenGroupCreation : newTokenGroups) {
        if (!tokenGroupCreation.ValidateDescription()) {
            LogPrint("token", "%s - Validation of token %s failed", __func__, EncodeTokenGroup(tokenGroupCreation.tokenGroupInfo.associatedGroup));
        }

        StoreManagementTokenGroups(tokenGroupCreation);

        auto ret = mapTokenGroups.insert(std::pair<CTokenGroupID, CTokenGroupCreation>(tokenGroupCreation.tokenGroupInfo.associatedGroup, tokenGroupCreation));

        CTokenGroupCreation& tokenGroupCreationRet = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (!fInsertedNew) {
            LogPrint("token", "%s - Double token creation with tokenGroupID %s.\n", __func__, EncodeTokenGroup(tokenGroupCreationRet.tokenGroupInfo.associatedGroup));
        }
    }
    return true;
}

void CTokenGroupManager::ResetTokenGroups() {
    mapTokenGroups.clear();
    ClearManagementTokenGroups();

    CTokenGroupInfo tgInfoION(NoGroup, (CAmount)GroupAuthorityFlags::ALL);
    CTransaction tgTxION;
    CTokenGroupDescription tgDescriptionION("ION", "Ion", 8, "https://www.ionomy.com", 0);
    CTokenGroupStatus tokenGroupStatus;
    CTokenGroupCreation tgCreationION(tgTxION, tgInfoION, tgDescriptionION, tokenGroupStatus);
    mapTokenGroups.insert(std::pair<CTokenGroupID, CTokenGroupCreation>(NoGroup, tgCreationION));

}

bool CTokenGroupManager::RemoveTokenGroup(CTransaction tx, CTokenGroupID &toRemoveTokenGroupID) {
    CScript firstOpReturn;
    CTokenGroupInfo tokenGroupInfo;

    bool hasNewTokenGroup = GetTokenConfigurationParameters(tx, tokenGroupInfo, firstOpReturn);

    if (hasNewTokenGroup) {
        if (MatchesMagic(tokenGroupInfo.associatedGroup)) {
            tgMagicCreation.reset();
        } else if (MatchesDarkMatter(tokenGroupInfo.associatedGroup)) {
            tgDarkMatterCreation.reset();
        } else if (MatchesAtom(tokenGroupInfo.associatedGroup)) {
            tgAtomCreation.reset();
        }

        std::map<CTokenGroupID, CTokenGroupCreation>::iterator iter = mapTokenGroups.find(tokenGroupInfo.associatedGroup);
        if (iter != mapTokenGroups.end()) {
            mapTokenGroups.erase(iter);
            toRemoveTokenGroupID = iter->first;
            return true;
        }
    }
    return false;
}

bool CTokenGroupManager::GetTokenGroupCreation(const CTokenGroupID& tgID, CTokenGroupCreation& tgCreation) {
    std::map<CTokenGroupID, CTokenGroupCreation>::iterator iter = mapTokenGroups.find(tgID);
    if (iter != mapTokenGroups.end()) {
        tgCreation = mapTokenGroups.at(tgID);
    } else {
        return false;
    }
    return true;
}
std::string CTokenGroupManager::GetTokenGroupNameByID(CTokenGroupID tokenGroupId) {
    CTokenGroupCreation tokenGroupCreation = mapTokenGroups.at(tokenGroupId);
    return "";
}

bool CTokenGroupManager::GetTokenGroupIdByTicker(std::string strTicker, CTokenGroupID &tokenGroupID) {
    std::string strNeedleTicker;
    std::transform(strTicker.begin(), strTicker.end(), std::back_inserter(strNeedleTicker), ::tolower);
    auto result = std::find_if(
        mapTokenGroups.begin(), mapTokenGroups.end(),
        [strNeedleTicker](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
            std::string strHeapTicker;
            std::transform(tokenGroup.second.tokenGroupDescription.strTicker.begin(),
                tokenGroup.second.tokenGroupDescription.strTicker.end(),
                std::back_inserter(strHeapTicker), ::tolower);
            return strHeapTicker == strNeedleTicker;
        });
    if (result != mapTokenGroups.end()) {
        tokenGroupID = result->first;
        return true;
    };
    return false;
}

bool CTokenGroupManager::GetTokenGroupIdByName(std::string strName, CTokenGroupID &tokenGroupID) {
    std::string strNeedleName;
    std::transform(strName.begin(), strName.end(), std::back_inserter(strNeedleName), ::tolower);
    auto result = std::find_if(
        mapTokenGroups.begin(), mapTokenGroups.end(),
        [strNeedleName](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
            std::string strHeapName;
            std::transform(tokenGroup.second.tokenGroupDescription.strName.begin(),
                tokenGroup.second.tokenGroupDescription.strName.end(),
                std::back_inserter(strHeapName), ::tolower);
            return strHeapName == strNeedleName;
        });
    if (result != mapTokenGroups.end()) {
        tokenGroupID = result->first;
        return true;
    };
    return false;
}

unsigned int CTokenGroupManager::GetTokenTxStats(const CTransaction &tx, const CCoinsViewCache& view, const CTokenGroupID &tgId,
                unsigned int &nTokenCount, CAmount &nTokenMint) {

    CAmount nTxValueOut = 0;
    CAmount nTxValueIn = 0;

    if (!tx.IsCoinBase() && !tx.IsCoinStake() && !tx.HasZerocoinSpendInputs()) {
        for (const auto &outp : tx.vout)
        {
            const CScript &scriptPubKey = outp.scriptPubKey;
            CTokenGroupInfo tokenGrp(scriptPubKey);
            if (!tokenGrp.invalid && tokenGrp.associatedGroup == tgId && !tokenGrp.isAuthority())
            {
                nTxValueOut += tokenGrp.quantity;
            }
        }
        for (const auto &inp : tx.vin)
        {
            const COutPoint &prevout = inp.prevout;
            const Coin &coin = view.AccessCoin(prevout);

            if (coin.nHeight < Params().OpGroup_StartHeight())
                continue;
            const CScript &script = coin.out.scriptPubKey;

            CTokenGroupInfo tokenGrp(script);
            if (!tokenGrp.invalid && tokenGrp.associatedGroup == tgId && !tokenGrp.isAuthority())
            {
                nTxValueIn += tokenGrp.quantity;
            }
        }
        nTokenMint += nTxValueOut - nTxValueIn;
        if (nTxValueIn > 0 || nTxValueOut > 0) {
            nTokenCount++;
        }
    }

    return nTokenCount;
}

bool CTokenGroupManager::TokenMoneyRange(CAmount nValueOut) {
    // Token amount max is 2^63-1 = 9223372036854775807
    return nValueOut >= 0 && nValueOut <= 922337203685477580;
}

CAmount CTokenGroupManager::AmountFromTokenValue(const UniValue& value, const CTokenGroupID& tgID) {
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    CTokenGroupCreation tgCreation;
    GetTokenGroupCreation(tgID, tgCreation);
    if (!ParseFixedPoint(value.getValStr(), tgCreation.tokenGroupDescription.nDecimalPos, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!TokenMoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

std::string CTokenGroupManager::TokenValueFromAmount(const CAmount& amount, const CTokenGroupID& tgID) {
    CTokenGroupCreation tgCreation;
    GetTokenGroupCreation(tgID, tgCreation);
    CAmount tokenCOIN = tgCreation.tokenGroupDescription.GetCoin();
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / tokenCOIN;
    int64_t remainder = n_abs % tokenCOIN;
    if (tgCreation.tokenGroupDescription.nDecimalPos == 0) {
        return strprintf("%s%d", sign ? "-" : "", quotient);
    } else {
        return strprintf("%s%d.%0*d", sign ? "-" : "", quotient, tgCreation.tokenGroupDescription.nDecimalPos, remainder);
    }
}

bool CTokenGroupManager::GetXDMFee(const uint32_t& nXDMTransactions, CAmount& fee) {
    if (!tgDarkMatterCreation) {
        fee = 0;
        return false;
    }
    CAmount XDMCoin = tgDarkMatterCreation->tokenGroupDescription.GetCoin();
    if (nXDMTransactions < 100000) {
        fee = 0.10 * XDMCoin;
    } else if (nXDMTransactions < 200000) {
        fee = 0.09 * XDMCoin;
    } else if (nXDMTransactions < 300000) {
        fee = 0.08 * XDMCoin;
    } else if (nXDMTransactions < 400000) {
        fee = 0.07 * XDMCoin;
    } else if (nXDMTransactions < 500000) {
        fee = 0.06 * XDMCoin;
    } else if (nXDMTransactions < 600000) {
        fee = 0.05 * XDMCoin;
    } else if (nXDMTransactions < 700000) {
        fee = 0.04 * XDMCoin;
    } else if (nXDMTransactions < 800000) {
        fee = 0.03 * XDMCoin;
    } else if (nXDMTransactions < 900000) {
        fee = 0.02 * XDMCoin;
    } else {
        fee = 0.01 * XDMCoin;
    }
    return true;
}

bool CTokenGroupManager::GetXDMFee(const CBlockIndex* pindex, CAmount& fee) {
    return GetXDMFee(pindex->nChainXDMTransactions, fee);
}

bool CTokenGroupManager::CheckXDMFees(const CTransaction &tx, const std::unordered_map<CTokenGroupID, CTokenGroupBalance>& tgMintMeltBalance, CValidationState& state, CBlockIndex* pindex, CAmount& nXDMFees) {
    if (!tgDarkMatterCreation) return true;
    // Creating a token costs a fee in XDM.
    // Fees are paid to an XDM management address.
    // 80% of the fees are burned weekly
    // 10% of the fees are distributed over masternode owners weekly
    // 10% of the fees are distributed over atom token holders weekly

    // A token group creation costs 5x the standard XDM fee
    // A token mint transaction costs 5x the standard XDM fee
    // Sending XDM costs 1x the standard XDM fee
    // When paying fees, there are 2 'free' XDM outputs (fee and change)

    CAmount XDMMelted = 0;
    CAmount XDMMinted = 0;
    CAmount XDMFeesPaid = 0;
    uint32_t nXDMOutputs = 0;
    uint32_t nXDMFreeOutputs = 0;

    CAmount curXDMFee;
    GetXDMFee(pindex, curXDMFee);

    nXDMFees = 0;

    for (auto txout : tx.vout) {
        CTokenGroupInfo grp(txout.scriptPubKey);
        if (grp.invalid)
            return false;
        if (grp.isGroupCreation() && !grp.associatedGroup.hasFlag(TokenGroupIdFlags::MGT_TOKEN)) {
            // Creation tx of regular token
            nXDMFees = 5 * curXDMFee;
            nXDMFreeOutputs = nXDMFreeOutputs < 2 ? 2 : nXDMFreeOutputs; // Free outputs for fee and change
        }
        if (MatchesDarkMatter(grp.associatedGroup) && !grp.isAuthority()) {
            // XDM output (send or mint)
            nXDMOutputs++;

            // Currenlty, fees are paid to the address belonging to the Token Management Key
            // TODO: change this to paying fees to the latest address that received an XDM Melt Authority
            CTxDestination payeeDest;
            ExtractDestination(txout.scriptPubKey, payeeDest);
            if (EncodeDestination(payeeDest) == Params().TokenManagementKey()) {
                XDMFeesPaid += grp.quantity;
            }
        }
    }
    for (auto bal : tgMintMeltBalance) {
        CTokenGroupCreation tgCreation;
        CTokenGroupID tgID = bal.first;
        CTokenGroupBalance tgBalance = bal.second;
        if (tgBalance.output - tgBalance.input > 0) {
            // Mint
            if (!tgID.hasFlag(TokenGroupIdFlags::MGT_TOKEN)) {
                // Regular token mint tx
                nXDMFees += 5 * curXDMFee;
                nXDMFreeOutputs = nXDMFreeOutputs < 2 ? 2 : nXDMFreeOutputs; // Fee free outputs for fee and change
            }
            if (tgID == tgDarkMatterCreation->tokenGroupInfo.associatedGroup) {
                // XDM mint
                XDMMinted += tgBalance.output - tgBalance.input;
                nXDMFreeOutputs = nXDMFreeOutputs < 1 ? 1 : nXDMFreeOutputs; // Fee free output for XDM mint
            }
        } else if (tgBalance.output - tgBalance.input < 0) {
            // Melt
            if (tgID == tgDarkMatterCreation->tokenGroupInfo.associatedGroup) {
                // XDM melt
                XDMMelted += tgBalance.output - tgBalance.input;
                nXDMFreeOutputs = nXDMFreeOutputs < 1 ? 1 : nXDMFreeOutputs; // Fee free output for XDM melt
            }
        }
    }
    nXDMFees += nXDMOutputs > nXDMFreeOutputs ?  1 * curXDMFee : 0;

    return XDMFeesPaid >= nXDMFees;
}

CAmount CTokenGroupManager::GetXDMFeesPaid(const std::vector<CRecipient> outputs) {
    CAmount XDMFeesPaid = 0;
    for (auto output : outputs) {
        CTxDestination payeeDest;
        if (ExtractDestination(output.scriptPubKey, payeeDest))
        {
            if (EncodeDestination(payeeDest) == Params().TokenManagementKey()) {
                CTokenGroupInfo tgInfo(output.scriptPubKey);
                if (MatchesDarkMatter(tgInfo.associatedGroup)) {
                    XDMFeesPaid += tgInfo.isAuthority() ? 0 : tgInfo.quantity;
                }
            }
        }
    }
    return XDMFeesPaid;
}

// Ensure that one of the recipients is an XDM fee payment
// If an output to the fee address already exists, it ensures that the output is at least XDMFee large
// Returns true if a new output is added and false if a current output is either increased or kept as-is
bool CTokenGroupManager::EnsureXDMFee(std::vector<CRecipient> &outputs, CAmount XDMFee) {
    if (!tgDarkMatterCreation) return false;
    if (XDMFee <= 0) return false;
    CTxDestination payeeDest;
    for (auto &output : outputs) {
        if (ExtractDestination(output.scriptPubKey, payeeDest))
        {
            if (EncodeDestination(payeeDest) == Params().TokenManagementKey()) {
                CTokenGroupInfo tgInfo(output.scriptPubKey);
                if (MatchesDarkMatter(tgInfo.associatedGroup) && !tgInfo.isAuthority()) {
                    if (tgInfo.quantity < XDMFee) {
                        CScript script = GetScriptForDestination(payeeDest, tgInfo.associatedGroup, XDMFee);
                        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};

                        output.scriptPubKey = script;
                        return false;
                    } else {
                        return false;
                    }
                }
            }
        }
    }
    CScript script = GetScriptForDestination(DecodeDestination(Params().TokenManagementKey()), tgDarkMatterCreation->tokenGroupInfo.associatedGroup, XDMFee);
    CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
    outputs.push_back(recipient);

    return true;
}
