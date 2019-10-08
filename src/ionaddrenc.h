// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2018 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_IONADDRENC_H
#define BITCOIN_IONADDRENC_H

#include "script/standard.h"

#include <string>
#include <vector>

class CChainParams;
class CTokenGroupID;

enum IONAddrType : uint8_t
{
    PUBKEY_TYPE = 0,
    SCRIPT_TYPE = 1,
    GROUP_TYPE = 2,
};

std::string EncodeIONAddr(const CTxDestination &, const CChainParams &);
std::string EncodeIONAddr(const std::vector<uint8_t> &id, const IONAddrType addrtype, const CChainParams &params);
std::string EncodeTokenGroup(const CTokenGroupID &grp, const CChainParams &params);
std::string EncodeTokenGroup(const CTokenGroupID &grp);

struct IONAddrContent
{
    IONAddrType type;
    std::vector<uint8_t> hash;
};

CTxDestination DecodeIONAddr(const std::string &addr, const CChainParams &params);
IONAddrContent DecodeIONAddrContent(const std::string &addr, const CChainParams &params);
CTxDestination DecodeIONAddrDestination(const IONAddrContent &content);

std::vector<uint8_t> PackIONAddrContent(const IONAddrContent &content);
#endif
