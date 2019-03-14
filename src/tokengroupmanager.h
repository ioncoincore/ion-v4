// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_MANAGER_H
#define TOKEN_GROUP_MANAGER_H

#include "wallet/wallet.h"

#include <unordered_map>

class CTokenGroupManager;
extern std::shared_ptr<CTokenGroupManager> tokenGroupManager;

class CTokenGroupDescription
{
public:
    // Token ticker name
    // Max 8 characters
    std::string strTicker;

    // Token name
    std::string strName;

    // Extended token description document URL
    std::string strDocumentUrl;

    uint256 documentHash;
    bool invalid;

    CTokenGroupDescription() : invalid(true) {};
    CTokenGroupDescription(std::string strTicker, std::string strName, std::string strDocumentUrl, uint256 documentHash) :
        strTicker(strTicker), strName(strName), strDocumentUrl(strDocumentUrl), documentHash(documentHash), invalid(false)
    {
        ValidateTokenDescription();
    };

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(strTicker);
        READWRITE(strName);
        READWRITE(strDocumentUrl);
        READWRITE(documentHash);
    }
    bool operator==(const CTokenGroupDescription &c)
    {
        return (strTicker == c.strTicker && strName == c.strName && strDocumentUrl == c.strDocumentUrl && documentHash == c.documentHash);
    }

    bool ValidateTokenDescription();
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
    CTokenGroupCreation tgManagementTokenCreation;
    CTokenGroupCreation tgDarkMatterCreation;
    CTokenGroupCreation tgAtomCreation;

public:
    CTokenGroupManager()
    {
    }

    bool AddTokenGroup(CTransaction tx, CTokenGroupCreation &newTokenGroupCreation);
    bool RemoveTokenGroup(CTransaction tx, CTokenGroupID &newTokenGroupID);

    std::string GetTokenGroupNameByID(CTokenGroupID tokenGroupId);
    int GetTokenGroupIdByName(std::string strName);
    std::map<CTokenGroupID, CTokenGroupCreation> GetMapTokenGroups() { return mapTokenGroups; };

    bool BuildGroupDescData(CScript script, std::vector<std::vector<unsigned char> > &descriptionData);
    bool ParseGroupDescData(const std::vector<std::vector<unsigned char> > descriptionData, CTokenGroupDescription &tokenGroupDescription);
};

#endif
