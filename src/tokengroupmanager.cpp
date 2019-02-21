// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokengroupmanager.h"

CTokenGroupManager tokenGroupManager;

bool CTokenGroupManager::addNewTokenGroup(CTransaction tx, CValidationState &state) {
    CScript firstOpReturn;
    CTokenGroupInfo newTokenGroupInfo;

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
            newTokenGroupInfo = tokenGrp;
        }
    }
    if (hasNewTokenGroup) {
        CTokenGroupCreation newTokenGroupCreation = CTokenGroupCreation(newTokenGroupInfo, tx);
        std::pair<std::map<CTokenGroupID, CTokenGroupCreation>::iterator, bool> ret;
        ret = mapTokenGroups.insert(std::pair<CTokenGroupID, CTokenGroupCreation>(newTokenGroupInfo.associatedGroup, newTokenGroupCreation));
        CTokenGroupCreation& tokenGroupCreation = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (!fInsertedNew) {
            mapTokenGroups[newTokenGroupInfo.associatedGroup] = newTokenGroupCreation;
            // Token ID already exists. Since the hash is the same, the token specs are the same.
            // However, until reorgs are handled properly: log this to avoid 'misplaced' token group creation transactions.
            LogPrintf("token", "%s - Double token creation", __func__);
        }

    }
    return true;
}
