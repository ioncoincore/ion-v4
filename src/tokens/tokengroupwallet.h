// Copyright (c) 2016-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_RPC_H
#define TOKEN_GROUP_RPC_H

#include "chainparams.h"
#include "consensus/tokengroups.h"
#include "wallet/wallet.h"
#include <unordered_map>

// Number of satoshis we will put into a grouped output
static const CAmount GROUPED_SATOSHI_AMT = 1;

// Pass a group and a destination address (or CNoDestination) to get the balance of all outputs in the group
// or all outputs in that group and on that destination address.
CAmount GetGroupBalance(const CTokenGroupID &grpID, const CTxDestination &dest, const CWallet *wallet);

// Returns a mapping of groupID->balance
void GetAllGroupBalances(const CWallet *wallet, std::unordered_map<CTokenGroupID, CAmount> &balances);
void GetAllGroupBalancesAndAuthorities(const CWallet *wallet, std::unordered_map<CTokenGroupID, CAmount> &balances,
    std::unordered_map<CTokenGroupID, GroupAuthorityFlags> &authorities);
void ListAllGroupAuthorities(const CWallet *wallet, std::vector<COutput> &coins);
void ListGroupAuthorities(const CWallet *wallet, std::vector<COutput> &coins, const CTokenGroupID &grpID);
void GetGroupBalanceAndAuthorities(CAmount &balance, GroupAuthorityFlags &authorities, const CTokenGroupID &grpID,
    const CTxDestination &dest, const CWallet *wallet);

// Token group helper functions -- not members because they use objects not available in the consensus lib
//* Initialize the group id from an address
CTokenGroupID GetTokenGroup(const CTxDestination &id);
//* Initialize a group ID from a string representation
CTokenGroupID GetTokenGroup(const std::string &ionAddrGrpId, const CChainParams &params = Params());

std::string EncodeTokenGroup(const CTokenGroupID &grp, const CChainParams &params = Params());

//* Calculate a group ID based on the provided inputs.  Pass and empty script to opRetTokDesc if there is not
// going to be an OP_RETURN output in the transaction.
CTokenGroupID findGroupId(const COutPoint &input, CScript opRetTokDesc, TokenGroupIdFlags flags, uint64_t &nonce);

CAmount GroupCoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins);
uint64_t RenewAuthority(const COutput &authority, std::vector<CRecipient> &outputs, CReserveKey &childAuthorityKey);

void ConstructTx(CWalletTx &wtxNew, const std::vector<COutput> &chosenCoins, const std::vector<CRecipient> &outputs,
    CAmount totalAvailable, CAmount totalNeeded, CAmount totalGroupedAvailable, CAmount totalGroupedNeeded,
    CAmount totalXDMAvailable, CAmount totalXDMNeeded, CTokenGroupID grpID, CWallet *wallet);

void GroupMelt(CWalletTx &wtxNew, const CTokenGroupID &grpID, CAmount totalNeeded, CWallet *wallet);
void GroupSend(CWalletTx &wtxNew, const CTokenGroupID &grpID, const std::vector<CRecipient> &outputs,
    CAmount totalNeeded, CAmount totalXDMNeeded, CWallet *wallet);


//* Group script helper function
CScript GetScriptForDestination(const CTxDestination &dest, const CTokenGroupID &group, const CAmount &amount);

#endif
