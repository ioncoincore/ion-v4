// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_MANAGER_H
#define TOKEN_GROUP_MANAGER_H

#include "wallet/wallet.h"

#include <unordered_map>

class CTokenGroupManager;
extern CTokenGroupManager tokenGroupManager;

class CTokenGroupCreation
{
public:
    CTokenGroupInfo tokenGroupInfo;
    CTransaction creationTransaction;

    CTokenGroupCreation(){};

    CTokenGroupCreation(CTokenGroupInfo tokenGroupInfoIn, CTransaction creationTransactionIn)
        : tokenGroupInfo(tokenGroupInfoIn), creationTransaction(creationTransactionIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(tokenGroupInfo);
        READWRITE(creationTransaction);
    }
    bool operator==(const CTokenGroupCreation &c)
    {
        if (c.tokenGroupInfo.invalid || tokenGroupInfo.invalid)
            return false;
        return ((tokenGroupInfo == c.tokenGroupInfo) && (creationTransaction == c.creationTransaction));
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

    bool addNewTokenGroup(CTransaction tx, CValidationState &state);

    std::string GetTokenGroupNameByID(int id);
    int GetTokenGroupIdByName(std::string strName);
};

#endif
