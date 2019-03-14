// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokengroupmanager.h"

#include "rpc/protocol.h"
#include "utilstrencodings.h"

#include <univalue.h>
#include <iostream>
#include <regex>
#include <string.h>

std::shared_ptr<CTokenGroupManager> tokenGroupManager;

bool CTokenGroupDescription::ValidateTokenDescription() {
    regex regexAlpha("^[a-zA-Z]+$");
    regex regexUrl(R"((https?|ftp)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$)");

    smatch matchResult;
    if (!std::regex_match(strName, matchResult, regexAlpha)) {
        LogPrint("token", "Token name can only contain letters.");
        invalid = true;
        return false;
    }
    if (!std::regex_match(strTicker, matchResult, regexAlpha)) {
        LogPrint("token", "Token ticker can only contain letters.");
        invalid = true;
        return false;
    }
    if (!std::regex_match(strDocumentUrl, matchResult, regexUrl)) {
        LogPrint("token", "Token description document URL cannot be parsed.");
        invalid = true;
        return false;
    }
    invalid = false;
    return true;
}

bool CTokenGroupManager::BuildGroupDescData(CScript script, std::vector<std::vector<unsigned char> > &descriptionData) {
    std::vector<std::vector<unsigned char> > desc;

    CScript::const_iterator pc = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;

    if (!script.GetOp(pc, opcode, data)) return false;
    if (opcode != OP_RETURN) return false;

    if (!script.GetOp(pc, opcode, data)) return false;
    uint32_t OpRetGroupId;
    if (data.size()!=4) return false;
    OpRetGroupId = (uint32_t)data[3] << 24 | (uint32_t)data[2] << 16 | (uint32_t)data[1] << 8 | (uint32_t)data[0];
    if (OpRetGroupId != 88888888) return false;

    while (script.GetOp(pc, opcode, data)) {
        LogPrintf("More data! opcode=[%d] data=[%s]\n", opcode, std::string(data.begin(), data.end()));
        desc.emplace_back(data);
    }
    descriptionData = desc;
    return true;
}

bool CTokenGroupManager::ParseGroupDescData(const std::vector<std::vector<unsigned char> > descriptionData, CTokenGroupDescription &tokenGroupDescription) {
    std::string tickerStr;
    std::string name;
    std::string url;
    uint256 docHash;

    try {
        tickerStr = std::string(descriptionData[0].begin(), descriptionData[0].end());
        name = std::string(descriptionData[1].begin(), descriptionData[1].end());
        url = std::string(descriptionData[2].begin(), descriptionData[2].end());
        docHash = uint256(descriptionData[3]);
    } catch (const std::exception& e) {
        return false;
    }
    CTokenGroupDescription tgDesc(tickerStr, name, url, docHash);
    if (tgDesc.ValidateTokenDescription()) tokenGroupDescription = tgDesc;

    return true;
}

bool CTokenGroupManager::addNewTokenGroup(CTransaction tx, CValidationState &state) {
    CScript firstOpReturn;
    CTokenGroupInfo tokenGroupInfo;

    bool hasNewTokenGroup = false;

    for (const auto &txout : tx.vout) {
        const CScript &scriptPubKey = txout.scriptPubKey;
        CTokenGroupInfo tokenGrp(scriptPubKey);
        if ((txout.nValue == 0) && (firstOpReturn.size() == 0) && (txout.scriptPubKey[0] == OP_RETURN)) {
            firstOpReturn = txout.scriptPubKey;
        }
        if (tokenGrp.invalid)
            return state.Invalid(false, REJECT_INVALID, "bad OP_GROUP");
        if (tokenGrp.associatedGroup != NoGroup && tokenGrp.isGroupCreation() && !hasNewTokenGroup) {
            hasNewTokenGroup = true;
            tokenGroupInfo = tokenGrp;
        }
    }
    if (hasNewTokenGroup) {
        CTokenGroupDescription tokenGroupDescription;
        if (firstOpReturn.size()) {
            std::vector<std::vector<unsigned char> > desc;
            if (BuildGroupDescData(firstOpReturn, desc)) {
                ParseGroupDescData(desc, tokenGroupDescription);
            }
        }

        CTokenGroupCreation tokenGroupCreation = CTokenGroupCreation(tx, tokenGroupInfo, tokenGroupDescription);

        std::pair<std::map<CTokenGroupID, CTokenGroupCreation>::iterator, bool> ret;
        ret = mapTokenGroups.insert(std::pair<CTokenGroupID, CTokenGroupCreation>(tokenGroupInfo.associatedGroup, tokenGroupCreation));

        CTokenGroupCreation& tokenGroupCreationRet = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (!fInsertedNew) {
            if (!(tokenGroupCreation == tokenGroupCreationRet)) {
                mapTokenGroups[tokenGroupInfo.associatedGroup] = tokenGroupCreation;
                // Token ID already exists. Since the hash is the same, the token specs are the same.
                // However, until reorgs are handled  properly: log this to avoid 'misplaced' token group creation transactions.
                LogPrint("token", "%s - Double token creation; updated.\n", __func__);
            } else {
                LogPrint("token", "%s - Double token creation; NOT updated.\n", __func__);
            }
        } else {
        }

    }
    return true;
}

std::string CTokenGroupManager::GetTokenGroupNameByID(CTokenGroupID tokenGroupId) {
    CTokenGroupCreation tokenGroupCreation = mapTokenGroups.at(tokenGroupId);
    return "";
}
