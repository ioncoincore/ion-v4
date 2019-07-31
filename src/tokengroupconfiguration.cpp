// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokengroupconfiguration.h"
#include "tokengroupmanager.h"
#include "wallet/tokengroupwallet.h"

#include <univalue.h>
#include <iostream>
#include <regex>
#include <string.h>

// Returns true if the first 5 bytes indicate the script contains a Token Group Description
// Output descriptionData[] holds 0 or more unverified char vectors of description data
bool CTokenGroupDescription::BuildGroupDescData(CScript script, std::vector<std::vector<unsigned char> > &descriptionData) {
    std::vector<std::vector<unsigned char> > desc;

    CScript::const_iterator pc = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;

    // 1 byte
    if (!script.GetOp(pc, opcode, data)) return false;
    if (opcode != OP_RETURN) return false;

    // 1+4 bytes
    if (!script.GetOp(pc, opcode, data)) return false;
    uint32_t OpRetGroupId;
    if (data.size()!=4) return false;
    // Little Endian
    OpRetGroupId = (uint32_t)data[3] << 24 | (uint32_t)data[2] << 16 | (uint32_t)data[1] << 8 | (uint32_t)data[0];
    if (OpRetGroupId != 88888888) return false;

    while (script.GetOp(pc, opcode, data)) {
        LogPrint("token", "Token description data: opcode=[%d] data=[%s]\n", opcode, std::string(data.begin(), data.end()));
        desc.emplace_back(data);
    }
    descriptionData = desc;
    return true;
}

// Returns true if the token description data fields have the correct maximum length
// On success, *this is initialized with the data fields
bool CTokenGroupDescription::SetGroupDescData(const std::vector<std::vector<unsigned char> > descriptionData) {

    auto it = descriptionData.begin();

    if (it == descriptionData.end()) return false;

    strTicker = GetStringFromChars(*it, 8); // Max 9 bytes (1+8)
    it++;

    if (it == descriptionData.end()) return false;
    strName = GetStringFromChars(*it, 32); // Max 33 bytes (1+32)
    it++;

    if (it == descriptionData.end()) return false;
    nDecimalPos = (uint8_t)(*it)[0]; // Max 1 byte
    it++;

    if (it == descriptionData.end()) return false;
    strDocumentUrl = GetStringFromChars(*it, 79); // Max 81 bytes (2+79)
    it++;

    if (it == descriptionData.end()) return false;
    try {
        documentHash = uint256(*it); // Max 33 bytes (1+32)
    } catch (const std::exception& e) {
        documentHash = 0;
    }

    return true;
}

bool CTokenGroupCreation::ValidateDescription() {
    for (auto tgFilters : tokenGroupManager->vTokenGroupFilters) {
        tgFilters(*this);
    }
    return true;
}

// Checks that the token description data fulfills basic criteria
// Such as: max ticker length, no special characters, and sane decimal positions.
// Validation is performed before data is written to the database
void TGFilterCharacters(CTokenGroupCreation &tokenGroupCreation) {
    regex regexAlpha("^[a-zA-Z]+$");
    regex regexAlphaNum("^[a-zA-Z0-9]+$");
    regex regexUrl(R"((https?|ftp)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$)");

    smatch matchResult;

    if (tokenGroupCreation.tokenGroupDescription.strTicker != "" && 
            !std::regex_match(tokenGroupCreation.tokenGroupDescription.strTicker, matchResult, regexAlpha)) {
        tokenGroupCreation.status.AddMessage("Token ticker can only contain letters.");
        tokenGroupCreation.tokenGroupDescription.strTicker = "";
    }
    if (tokenGroupCreation.tokenGroupDescription.strName != "" && 
            !std::regex_match(tokenGroupCreation.tokenGroupDescription.strName, matchResult, regexAlpha)) {
        tokenGroupCreation.status.AddMessage("Token name can only contain letters.");
        tokenGroupCreation.tokenGroupDescription.strName = "";
    }
    if (tokenGroupCreation.tokenGroupDescription.strDocumentUrl != "" && 
            !std::regex_match(tokenGroupCreation.tokenGroupDescription.strDocumentUrl, matchResult, regexUrl)) {
        tokenGroupCreation.status.AddMessage("Token description document URL cannot be parsed.");
        tokenGroupCreation.tokenGroupDescription.strDocumentUrl = "";
    }
    if (tokenGroupCreation.tokenGroupDescription.nDecimalPos > 16) {
        tokenGroupCreation.status.AddMessage("Token decimal separation position is too large.");
        tokenGroupCreation.tokenGroupDescription.nDecimalPos = 8;
    }
}

// Checks that the token description data fulfils context dependent criteria
// Such as: no reserved names, no double names
// Validation is performed after data is written to the database and before it is written to the map
void TGFilterUniqueness(CTokenGroupCreation &tokenGroupCreation) {
    // Iterate existing token groups and verify that the new group has an unique ticker and name
    std::string strLowerTicker;
    std::string strLowerName;
    std::transform(tokenGroupCreation.tokenGroupDescription.strTicker.begin(), tokenGroupCreation.tokenGroupDescription.strTicker.end(), std::back_inserter(strLowerTicker), ::tolower);
    std::transform(tokenGroupCreation.tokenGroupDescription.strName.begin(), tokenGroupCreation.tokenGroupDescription.strName.end(), std::back_inserter(strLowerName), ::tolower);

    CTokenGroupID tgID = tokenGroupCreation.tokenGroupInfo.associatedGroup;

    std::map<CTokenGroupID, CTokenGroupCreation> mapTGs = tokenGroupManager->GetMapTokenGroups();

    if (strLowerTicker != "") {
        std::find_if(
            mapTGs.begin(),
            mapTGs.end(),
            [strLowerTicker, tgID, &tokenGroupCreation](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
                    // Only try to match with valid token groups
                    if (tokenGroup.second.tokenGroupInfo.invalid) return false;

                    // If the ID is the same, the token group is the same
                    if (tokenGroup.second.tokenGroupInfo.associatedGroup == tgID) return false;

                    // Compare lower case
                    std::string strHeapTicker;
                    std::transform(tokenGroup.second.tokenGroupDescription.strTicker.begin(),
                        tokenGroup.second.tokenGroupDescription.strTicker.end(),
                        std::back_inserter(strHeapTicker), ::tolower);
                    if (strLowerTicker == strHeapTicker){
                        tokenGroupCreation.status.AddMessage("Token ticker already exists.");
                        tokenGroupCreation.tokenGroupDescription.strTicker = "";
                        return true;
                    }

                    return false;
                });
    }

    if (strLowerName != "") {
        std::find_if(
            mapTGs.begin(),
            mapTGs.end(),
            [strLowerName, tgID, &tokenGroupCreation](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
                    // Only try to match with valid token groups
                    if (tokenGroup.second.tokenGroupInfo.invalid) return false;

                    // If the ID is the same, the token group is the same
                    if (tokenGroup.second.tokenGroupInfo.associatedGroup == tgID) return false;

                    std::string strHeapName;
                    std::transform(tokenGroup.second.tokenGroupDescription.strName.begin(),
                        tokenGroup.second.tokenGroupDescription.strName.end(),
                        std::back_inserter(strHeapName), ::tolower);
                    if (strLowerName == strHeapName){
                        tokenGroupCreation.status.AddMessage("Token name already exists.");
                        tokenGroupCreation.tokenGroupDescription.strName = "";
                        return true;
                    }

                    return false;
                });
    }
}

// Transforms tickers into upper case
// Returns true
void TGFilterUpperCaseTicker(CTokenGroupCreation &tokenGroupCreation) {
    std::string strUpperTicker;
    std::transform(tokenGroupCreation.tokenGroupDescription.strTicker.begin(), tokenGroupCreation.tokenGroupDescription.strTicker.end(), std::back_inserter(strUpperTicker), ::toupper);

    tokenGroupCreation.tokenGroupDescription.strTicker = strUpperTicker;
}

bool GetTokenConfigurationParameters(const CTransaction &tx, CTokenGroupInfo &tokenGroupInfo, CScript &firstOpReturn) {
    bool hasNewTokenGroup = false;
    for (const auto &txout : tx.vout) {
        const CScript &scriptPubKey = txout.scriptPubKey;
        CTokenGroupInfo tokenGrp(scriptPubKey);
        if ((txout.nValue == 0) && (firstOpReturn.size() == 0) && (txout.scriptPubKey[0] == OP_RETURN)) {
            firstOpReturn = txout.scriptPubKey;
        }
        if (tokenGrp.invalid)
            return false;
        if (tokenGrp.associatedGroup != NoGroup && tokenGrp.isGroupCreation() && !hasNewTokenGroup) {
            hasNewTokenGroup = true;
            tokenGroupInfo = tokenGrp;
        }
    }
    return hasNewTokenGroup;

}

bool CreateTokenGroup(CTransaction tx, CTokenGroupCreation &newTokenGroupCreation) {
    CScript firstOpReturn;
    CTokenGroupInfo tokenGroupInfo;

    if (!GetTokenConfigurationParameters(tx, tokenGroupInfo, firstOpReturn)) return false;

    CTokenGroupDescription tokenGroupDescription = CTokenGroupDescription(firstOpReturn);
    CTokenGroupStatus tokenGroupStatus;
    newTokenGroupCreation = CTokenGroupCreation(tx, tokenGroupInfo, tokenGroupDescription, tokenGroupStatus);

    return true;
}
