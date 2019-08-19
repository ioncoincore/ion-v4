// Copyright (c) 2017-2018 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RPC_BLOCKCHAIN_H
#define RPC_BLOCKCHAIN_H

#include "amount.h"
#include "consensus/tokengroups.h"
#include "script/standard.h"

#include <unordered_map>
#include <vector>

/** Used to get a list of token owners to pay  */
void GetChainTokenBalances(std::unordered_map<std::string, CAmount>& mAtomBalances, CAmount& nAtomCount, const CTokenGroupID& needle);

#endif
