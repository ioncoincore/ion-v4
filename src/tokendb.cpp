// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokendb.h"
#include "tokengroupmanager.h"

CTokenDB::CTokenDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDBWrapper(GetDataDir() / "tokens", nCacheSize, fMemory, fWipe) {}

bool CTokenDB::WriteTokenGroupsBatch(const std::vector<CTokenGroupCreation>& tokenGroups) {
    CLevelDBBatch batch;
    for (std::vector<CTokenGroupCreation>::const_iterator it = tokenGroups.begin(); it != tokenGroups.end(); it++){
        batch.Write(std::make_pair('c', it->tokenGroupInfo.associatedGroup), *it);
    }
    return WriteBatch(batch);
}

bool CTokenDB::WriteTokenGroup(const CTokenGroupID& tokenGroupID, const CTokenGroupCreation& tokenGroupCreation) {
    return Write(std::make_pair('c', tokenGroupID), tokenGroupCreation);
}

bool CTokenDB::ReadTokenGroup(const CTokenGroupID& tokenGroupID, CTokenGroupCreation& tokenGroupCreation) {
    return Read(std::make_pair('c', tokenGroupID), tokenGroupCreation);
}

bool CTokenDB::EraseTokenGroupBatch(const std::vector<CTokenGroupID>& newTokenGroupIDs) {
    CLevelDBBatch batch;
    for (std::vector<CTokenGroupID>::const_iterator it = newTokenGroupIDs.begin(); it != newTokenGroupIDs.end(); it++){
        batch.Erase(std::make_pair('c', *it));
    }
    return WriteBatch(batch);

}

bool CTokenDB::EraseTokenGroup(const CTokenGroupID& tokenGroupID) {
    return Erase(std::make_pair('c', tokenGroupID));
}

bool CTokenDB::DropTokenGroups() {
    return true;
}

bool CTokenDB::LoadTokensFromDB(std::string &strError) {
    tokenGroupManager->ResetTokenGroups();

    boost::scoped_ptr<CLevelDBIterator> pcursor(NewIterator());

    std::vector<CTokenGroupCreation> vTokenGroups;

    pcursor->SeekToFirst();

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, CTokenGroupID> key;
        if (pcursor->GetKey(key) && key.first == 'c') {
            CTokenGroupCreation tokenGroupCreation;
            if (pcursor->GetValue(tokenGroupCreation)) {
                if (tokenGroupManager->CreateTokenGroup(tokenGroupCreation.creationTransaction, tokenGroupCreation)) {
                    vTokenGroups.push_back(tokenGroupCreation);
                }
            } else {
                return error("LoadTokensFromDB() : failed to read value");
            }
        }
        pcursor->Next();
    }
    tokenGroupManager->AddTokenGroups(vTokenGroups);
    return true;
}

bool ReindexTokenDB(std::string &strError) {
    if (!pTokenDB->DropTokenGroups()) {
        strError = "Failed to reset token database";
        return false;
    }
    tokenGroupManager->ResetTokenGroups();

    uiInterface.ShowProgress(_("Reindexing token database..."), 0);

    CBlockIndex* pindex = chainActive[Params().OpGroup_StartHeight()];
    std::vector<CTokenGroupCreation> vTokenGroups;
    while (pindex) {
        uiInterface.ShowProgress(_("Reindexing token database..."), std::max(1, std::min(99, (int)((double)(pindex->nHeight - Params().OpGroup_StartHeight()) / (double)(chainActive.Height() - Params().OpGroup_StartHeight()) * 100))));

        if (pindex->nHeight % 1000 == 0)
            LogPrintf("Reindexing token database: block %d...\n", pindex->nHeight);

        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            strError = "Reindexing token database failed";
            return false;
        }

        for (const CTransaction& tx : block.vtx) {
            if (!tx.IsCoinBase() && !tx.HasZerocoinSpendInputs() && IsAnyOutputGroupedCreation(tx)) {
                LogPrint("token", "%s - tx with token create: [%s]\n", __func__, tx.HexStr());
                CTokenGroupCreation tokenGroupCreation;
                if (tokenGroupManager->CreateTokenGroup(tx, tokenGroupCreation)) {
                    vTokenGroups.push_back(tokenGroupCreation);
                }
            }
        }

        // Write the token database to disk every 100 blocks
        if (pindex->nHeight % 100 == 0) {
            if (!vTokenGroups.empty() && !pTokenDB->WriteTokenGroupsBatch(vTokenGroups)) {
                strError = "Error writing token database to disk";
                return false;
            }
            tokenGroupManager->AddTokenGroups(vTokenGroups);
            vTokenGroups.clear();
        }

        pindex = chainActive.Next(pindex);
    }
    uiInterface.ShowProgress("", 100);

    // Final flush to disk in case any remaining information exists
    if (!vTokenGroups.empty() && !pTokenDB->WriteTokenGroupsBatch(vTokenGroups)) {
        strError = "Error writing token database to disk";
        return false;
    }

    uiInterface.ShowProgress("", 100);

    return true;
}
