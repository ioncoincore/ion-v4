// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_MANAGER_H
#define TOKEN_GROUP_MANAGER_H

#include "tokengroupconfiguration.h"
#include "wallet/wallet.h"

#include <unordered_map>
#include <univalue.h>

class CTokenGroupManager;
extern std::shared_ptr<CTokenGroupManager> tokenGroupManager;

// TokenGroup Class
// Keeps track of all of the token groups
class CTokenGroupManager
{
private:
    std::map<CTokenGroupID, CTokenGroupCreation> mapTokenGroups;
    std::unique_ptr<CTokenGroupCreation> tgMagicCreation;
    std::unique_ptr<CTokenGroupCreation> tgDarkMatterCreation;
    std::unique_ptr<CTokenGroupCreation> tgAtomCreation;

public:
    CTokenGroupManager();

    std::vector<std::function<void (CTokenGroupCreation&)>> vTokenGroupFilters;

    bool AddTokenGroups(const std::vector<CTokenGroupCreation>& newTokenGroups);
    bool RemoveTokenGroup(CTransaction tx, CTokenGroupID &toRemoveTokenGroupID);
    void ResetTokenGroups();

    bool GetTokenGroupCreation(const CTokenGroupID& tgID, CTokenGroupCreation& tgCreation);
    std::string GetTokenGroupNameByID(CTokenGroupID tokenGroupId);
    bool GetTokenGroupIdByTicker(std::string strTicker, CTokenGroupID &tokenGroupID);
    bool GetTokenGroupIdByName(std::string strName, CTokenGroupID &tokenGroupID);
    std::map<CTokenGroupID, CTokenGroupCreation> GetMapTokenGroups() { return mapTokenGroups; };

    bool BuildGroupDescData(CScript script, std::vector<std::vector<unsigned char> > &descriptionData);
    bool ParseGroupDescData(const CTokenGroupInfo &tgInfo, const std::vector<std::vector<unsigned char> > descriptionData, CTokenGroupDescription &tokenGroupDescription);

    bool StoreManagementTokenGroups(CTokenGroupCreation tokenGroupCreation);
    void ClearManagementTokenGroups();

    bool MatchesMagic(CTokenGroupID tgID);
    bool MatchesDarkMatter(CTokenGroupID tgID);
    bool MatchesAtom(CTokenGroupID tgID);

    CTokenGroupID GetMagicID() { return tgMagicCreation->tokenGroupInfo.associatedGroup; };
    CTokenGroupID GetDarkMatterID() { return tgDarkMatterCreation->tokenGroupInfo.associatedGroup; };
    CTokenGroupID GetAtomID() { return tgAtomCreation->tokenGroupInfo.associatedGroup; };

    bool MagicTokensCreated();
    bool DarkMatterTokensCreated();
    bool AtomTokensCreated();

    bool ManagementTokensCreated() {
        return MagicTokensCreated() && DarkMatterTokensCreated() && AtomTokensCreated();
    }
    bool IsManagementTokenInput(CScript script);

    unsigned int GetTokenTxStats(const CTransaction &tx, const CCoinsViewCache& view, const CTokenGroupID &tgId, unsigned int &nTokenCount, CAmount &nTokenMint);

    bool TokenMoneyRange(CAmount nValueOut);
    CAmount AmountFromTokenValue(const UniValue& value, const CTokenGroupID& tgID);
    UniValue TokenValueFromAmount(const CAmount& amount, const CTokenGroupID& tgID);

    bool GetXDMFee(const uint32_t& nXDMTransactions, CAmount& fee);
    bool GetXDMFee(const CBlockIndex* pindex, CAmount& fee);

    bool CheckXDMFees(const CTransaction &tx, const std::unordered_map<CTokenGroupID, CTokenGroupBalance>& tgMintMeltBalance, CValidationState& state, CBlockIndex* pindex, CAmount& nXDMFees);
    CAmount GetXDMFeesPaid(const std::vector<CRecipient> outputs);
    bool EnsureXDMFee(std::vector<CRecipient> &outputs, CAmount XDMFee);
};

#endif
