// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_MANAGER_H
#define TOKEN_GROUP_MANAGER_H

#include "wallet/wallet.h"

#include <unordered_map>
#include <univalue.h>

class CTokenGroupManager;
extern std::shared_ptr<CTokenGroupManager> tokenGroupManager;

static CAmount COINFromDecimalPos(const uint8_t& decimalPos) {
    uint8_t n = decimalPos < 16 ? decimalPos : 0;
    static CAmount pow10[16] = {
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000,
        100000000, 1000000000, 10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000, 1000000000000000
    };

    return pow10[n];
}

class CTokenGroupDescription
{
public:
    // Token ticker name
    // Max 8 characters
    std::string strTicker;

    // Token name
    std::string strName;

    // Decimal position to translate between token value and amount
    uint8_t decimalPos;

    // Extended token description document URL
    std::string strDocumentUrl;

    uint256 documentHash;
    bool invalid;

    CTokenGroupDescription() : invalid(true) { };
    CTokenGroupDescription(std::string strTicker, std::string strName, uint8_t decimalPosIn, std::string strDocumentUrl, uint256 documentHash) :
        strTicker(strTicker), strName(strName), strDocumentUrl(strDocumentUrl), documentHash(documentHash), invalid(false)
    {
        decimalPos = decimalPosIn <= 16 ? decimalPosIn : 0;
    };

    void Clear() {
        strTicker = "";
        strName = "";
        decimalPos = 0; // Tokens with no fractional quantities have decimalPos=0
        strDocumentUrl = "";
        documentHash = uint256();
    }

    // Tokens with no fractional quantities have decimalPos=0
    // ION has has decimalpos=8 (1 ION is 100000000 satoshi)
    // Maximum value is 10^16
    CAmount GetCoin() {
        return COINFromDecimalPos(decimalPos);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(strTicker);
        READWRITE(strName);
        READWRITE(decimalPos);
        READWRITE(strDocumentUrl);
        READWRITE(documentHash);
    }
    bool operator==(const CTokenGroupDescription &c)
    {
        return (strTicker == c.strTicker && strName == c.strName && decimalPos == c.decimalPos && strDocumentUrl == c.strDocumentUrl && documentHash == c.documentHash);
    }
};

class CTokenGroupCreation
{
public:
    CTransaction creationTransaction;
    CTokenGroupInfo tokenGroupInfo;
    CTokenGroupDescription tokenGroupDescription;

    CTokenGroupCreation(){};

    CTokenGroupCreation(CTransaction creationTransaction, CTokenGroupInfo tokenGroupInfo, CTokenGroupDescription tokenGroupDescription)
        : creationTransaction(creationTransaction), tokenGroupInfo(tokenGroupInfo), tokenGroupDescription(tokenGroupDescription) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(creationTransaction);
        READWRITE(tokenGroupInfo);
        READWRITE(tokenGroupDescription);
    }
    bool operator==(const CTokenGroupCreation &c)
    {
        if (c.tokenGroupInfo.invalid || tokenGroupInfo.invalid)
            return false;
        return (creationTransaction == c.creationTransaction && tokenGroupInfo == c.tokenGroupInfo && tokenGroupDescription == c.tokenGroupDescription);
    }
};

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
    CTokenGroupManager() {
    }

    bool AddTokenGroups(const std::vector<CTokenGroupCreation>& newTokenGroups);
    bool CreateTokenGroup(CTransaction tx, CTokenGroupCreation &newTokenGroupCreation);
    bool RemoveTokenGroup(CTransaction tx, CTokenGroupID &newTokenGroupID);
    void ResetTokenGroups();

    bool GetTokenGroupCreation(const CTokenGroupID& tgID, CTokenGroupCreation& tgCreation);
    std::string GetTokenGroupNameByID(CTokenGroupID tokenGroupId);
    bool GetTokenGroupIdByTicker(std::string strTicker, CTokenGroupID &tokenGroupID);
    bool GetTokenGroupIdByName(std::string strName, CTokenGroupID &tokenGroupID);
    std::map<CTokenGroupID, CTokenGroupCreation> GetMapTokenGroups() { return mapTokenGroups; };

    bool BuildGroupDescData(CScript script, std::vector<std::vector<unsigned char> > &descriptionData);
    bool ParseGroupDescData(const CTokenGroupInfo &tgInfo, const std::vector<std::vector<unsigned char> > descriptionData, CTokenGroupDescription &tokenGroupDescription);

    bool ProcessManagementTokenGroups(CTokenGroupCreation tokenGroupCreation);
    void ClearManagementTokenGroups();

    unsigned int GetXDMTxCount(const CBlock &block, const CCoinsViewCache& view, unsigned int &nXDMCount);
    bool IsXDMTx(const CTransaction &transaction, const CCoinsViewCache& inputs);

    bool ValidateTokenDescription(const CTokenGroupInfo &tgInfo, const CTokenGroupDescription &tgDesc);

    bool TokenMoneyRange(CAmount nValueOut);
    CAmount AmountFromTokenValue(const UniValue& value, const CTokenGroupID& tgID);
    UniValue TokenValueFromAmount(const CAmount& amount, const CTokenGroupID& tgID);
};

#endif
