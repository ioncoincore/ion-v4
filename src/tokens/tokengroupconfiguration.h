// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_CONFIGURATION_H
#define TOKEN_GROUP_CONFIGURATION_H

#include "tokens/tokengroupdescription.h"
#include "wallet/wallet.h"

#include <unordered_map>
#include <univalue.h>

class CTokenGroupStatus
{
public:
    UniValue messages;

    CTokenGroupStatus() {
        messages = UniValue(UniValue::VARR);
    };

    void AddMessage(std::string statusMessage) {
        messages.push_back(statusMessage);
    }
};

class CTokenGroupCreation
{
public:
    CTransaction creationTransaction;
    CTokenGroupInfo tokenGroupInfo;
    CTokenGroupDescription tokenGroupDescription;
    CTokenGroupStatus status;

    CTokenGroupCreation(){};

    CTokenGroupCreation(CTransaction creationTransaction, CTokenGroupInfo tokenGroupInfo, CTokenGroupDescription tokenGroupDescription, CTokenGroupStatus tokenGroupStatus)
        : creationTransaction(creationTransaction), tokenGroupInfo(tokenGroupInfo), tokenGroupDescription(tokenGroupDescription), status(tokenGroupStatus) {}

    bool ValidateDescription();

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

void TGFilterCharacters(CTokenGroupCreation &tokenGroupCreation);
void TGFilterUniqueness(CTokenGroupCreation &tokenGroupCreation);
void TGFilterUpperCaseTicker(CTokenGroupCreation &tokenGroupCreation);

bool GetTokenConfigurationParameters(const CTransaction &tx, CTokenGroupInfo &tokenGroupInfo, CScript &firstOpReturn);
bool CreateTokenGroup(CTransaction tx, CTokenGroupCreation &newTokenGroupCreation);

#endif
