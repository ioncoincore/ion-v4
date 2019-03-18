// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "checkpoints.h"
#include "clientversion.h"
#include "consensus/validation.h"
#include "dstencode.h"
#include "main.h"
#include "rpc/server.h"
#include "sync.h"
#include "consensus/tokengroups.h"
#include "wallet/tokengroupwallet.h"
#include "txdb.h"
#include "util.h"
#include "utilmoneystr.h"
#include "xion/accumulatormap.h"
#include "xion/accumulators.h"
#include "wallet/wallet.h"
#include "xion/xionmodule.h"
#include "xionchain.h"

#include <stdint.h>
#include <fstream>
#include <iostream>
#include <univalue.h>
#include <mutex>
#include <numeric>
#include <condition_variable>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

using namespace std;

struct CUpdatedBlock
{
    uint256 hash;
    int height;
};
static std::mutex cs_blockchange;
static std::condition_variable cond_blockchange;
static CUpdatedBlock latestblock;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL) {
        if (chainActive.Tip() == NULL)
            return 1.0;
        else
            blockindex = chainActive.Tip();
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", blockindex->nVersion));
    result.push_back(Pair("merkleroot", blockindex->hashMerkleRoot.GetHex()));
    result.push_back(Pair("time", (int64_t)blockindex->nTime));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)blockindex->nNonce));
    result.push_back(Pair("bits", strprintf("%08x", blockindex->nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));
    result.push_back(Pair("acc_checkpoint", blockindex->nAccumulatorCheckpoint.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("acc_checkpoint", block.nAccumulatorCheckpoint.GetHex()));
    UniValue txs(UniValue::VARR);
    for (const CTransaction& tx : block.vtx) {
        if (txDetails) {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, uint256(0), objTx);
            txs.push_back(objTx);
        } else
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex* pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("modifier", strprintf("%016x", blockindex->nStakeModifier)));

    result.push_back(Pair("moneysupply",ValueFromAmount(blockindex->nMoneySupply)));
    result.push_back(Pair("XDM_transactions", (uint64_t)blockindex->nXDMTransactions));

    UniValue xionObj(UniValue::VOBJ);
    for (auto denom : libzerocoin::zerocoinDenomList) {
        xionObj.push_back(Pair(to_string(denom), ValueFromAmount(blockindex->mapZerocoinSupply.at(denom) * (denom*COIN))));
    }
    xionObj.push_back(Pair("total", ValueFromAmount(blockindex->GetZerocoinSupply())));
    result.push_back(Pair("xIONsupply", xionObj));

    return result;
}

UniValue getchecksumblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "getchecksumblock\n"
            "\nFinds the first occurrence of a certain accumulator checksum."
            "\nReturns the block hash or, if fVerbose=true, the JSON block object\n"

            "\nArguments:\n"
            "1. \"checksum\"      (string, required) The hex encoded accumulator checksum\n"
            "2. \"denom\"         (integer, required) The denomination of the accumulator\n"
            "3. fVerbose          (boolean, optional, default=false) true for a json object, false for the hex encoded hash\n"

            "\nResult (for fVerbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "  \"moneysupply\" : \"supply\"       (numeric) The money supply when this block was added to the blockchain\n"
            "  \"xIONsupply\" :\n"
            "  {\n"
            "     \"1\" : n,            (numeric) supply of 1 xION denomination\n"
            "     \"5\" : n,            (numeric) supply of 5 xION denomination\n"
            "     \"10\" : n,           (numeric) supply of 10 xION denomination\n"
            "     \"50\" : n,           (numeric) supply of 50 xION denomination\n"
            "     \"100\" : n,          (numeric) supply of 100 xION denomination\n"
            "     \"500\" : n,          (numeric) supply of 500 xION denomination\n"
            "     \"1000\" : n,         (numeric) supply of 1000 xION denomination\n"
            "     \"5000\" : n,         (numeric) supply of 5000 xION denomination\n"
            "     \"total\" : n,        (numeric) The total supply of all xION denominations\n"
            "  }\n"
            "}\n"

            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"

            "\nExamples:\n" +
            HelpExampleCli("getchecksumblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\", 5") +
            HelpExampleRpc("getchecksumblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\", 5"));


    LOCK(cs_main);

    // param 0
    std::string acc_checksum_str = params[0].get_str();
    uint256 checksum_256(acc_checksum_str);
    uint32_t acc_checksum = checksum_256.Get32();
    // param 1
    libzerocoin::CoinDenomination denomination = libzerocoin::IntToZerocoinDenomination(params[1].get_int());
    // param 2
    bool fVerbose = false;
    if (params.size() > 2)
        fVerbose = params[2].get_bool();

    int checksumHeight = GetChecksumHeight(acc_checksum, denomination);

    if (checksumHeight == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = chainActive[checksumHeight];

    if (!fVerbose)
        return pblockindex->GetBlockHash().GetHex();

    CBlock block;
    if (!ReadBlockFromDisk(block, pblockindex))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    return blockToJSON(block, pblockindex);
}


UniValue getblockcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"

            "\nResult:\n"
            "n    (numeric) The current block count\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", ""));

    LOCK(cs_main);
    return chainActive.Height();
}

UniValue getbestblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"

            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"

            "\nExamples\n" +
            HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", ""));

    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash().GetHex();
}

void RPCNotifyBlockChange(const uint256 hashBlock)
{
    CBlockIndex* pindex = nullptr;
    pindex = mapBlockIndex.at(hashBlock);
    if(pindex) {
        std::lock_guard<std::mutex> lock(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

UniValue waitfornewblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "waitfornewblock ( timeout )\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"

            "\nArguments:\n"
            "1. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"

            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
        );
    int timeout = 0;
    if (params.size() > 0)
        timeout = params[0].get_int();
    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue waitforblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "waitforblock blockhash ( timeout )\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"

            "\nArguments:\n"
            "1. \"blockhash\" (required, string) Block hash to wait for.\n"
            "2. timeout       (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"

            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
        );
    int timeout = 0;

    uint256 hash = uint256S(params[0].get_str());

    if (params.size() > 1)
        timeout = params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]{return latestblock.hash == hash || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]{return latestblock.hash == hash || !IsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue waitforblockheight(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "waitforblockheight height ( timeout )\n"
            "\nWaits for (at least) block height and returns the height and hash\n"
            "of the current tip.\n"
            "\nReturns the current block on timeout or exit.\n"

            "\nArguments:\n"
            "1. height  (required, int) Block height to wait for (int)\n"
            "2. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"

            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("waitforblockheight", "\"100\", 1000")
            + HelpExampleRpc("waitforblockheight", "\"100\", 1000")
        );
    int timeout = 0;

    int height = params[0].get_int();

    if (params.size() > 1)
        timeout = params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]{return latestblock.height >= height || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&height]{return latestblock.height >= height || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"

            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"

            "\nExamples:\n" +
            HelpExampleCli("getdifficulty", "") + HelpExampleRpc("getdifficulty", ""));

    LOCK(cs_main);
    return GetDifficulty();
}


UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose) {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        for (const PAIRTYPE(uint256, CTxMemPoolEntry) & entry : mempool.mapTx) {
            const uint256& hash = entry.first;
            const CTxMemPoolEntry& e = entry.second;
            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("size", (int)e.GetTxSize()));
            info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
            info.push_back(Pair("time", e.GetTime()));
            info.push_back(Pair("height", (int)e.GetHeight()));
            info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
            info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height())));
            const CTransaction& tx = e.GetTx();
            set<string> setDepends;
            for (const CTxIn& txin : tx.vin) {
                if (mempool.exists(txin.prevout.hash))
                    setDepends.insert(txin.prevout.hash.ToString());
            }

            UniValue depends(UniValue::VARR);
            for (const string& dep : setDepends) {
                depends.push_back(dep);
            }

            info.push_back(Pair("depends", depends));
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    } else {
        vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256& hash : vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"

            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"

            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"

            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            "    \"size\" : n,             (numeric) transaction size in bytes\n"
            "    \"fee\" : n,              (numeric) transaction fee in ion\n"
            "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
            "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
            "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
            "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
            "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
            "        \"transactionid\",    (string) parent transaction id\n"
            "       ... ]\n"
            "  }, ...\n"
            "]\n"

            "\nExamples\n" +
            HelpExampleCli("getrawmempool", "true") + HelpExampleRpc("getrawmempool", "true"));

    LOCK(cs_main);

    bool fVerbose = false;
    if (params.size() > 0)
        fVerbose = params[0].get_bool();

    return mempoolToJSON(fVerbose);
}

UniValue getblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"

            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"

            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockhash", "1000") + HelpExampleRpc("getblockhash", "1000"));

    LOCK(cs_main);

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue getblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbose is true, returns an Object with information about block <hash>.\n"

            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"

            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "  \"moneysupply\" : \"supply\"       (numeric) The money supply when this block was added to the blockchain\n"
            "  \"xIONsupply\" :\n"
            "  {\n"
            "     \"1\" : n,            (numeric) supply of 1 xION denomination\n"
            "     \"5\" : n,            (numeric) supply of 5 xION denomination\n"
            "     \"10\" : n,           (numeric) supply of 10 xION denomination\n"
            "     \"50\" : n,           (numeric) supply of 50 xION denomination\n"
            "     \"100\" : n,          (numeric) supply of 100 xION denomination\n"
            "     \"500\" : n,          (numeric) supply of 500 xION denomination\n"
            "     \"1000\" : n,         (numeric) supply of 1000 xION denomination\n"
            "     \"5000\" : n,         (numeric) supply of 5000 xION denomination\n"
            "     \"total\" : n,        (numeric) The total supply of all xION denominations\n"
            "  }\n"
            "}\n"

            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"

            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!ReadBlockFromDisk(block, pblockindex))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}

UniValue getblockheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash' header.\n"
            "If verbose is true, returns an Object with information about block <hash> header.\n"

            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"

            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "}\n"

            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash' header.\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockheaderToJSON(pblockindex);
}

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nSerializedSize;
    uint256 hashSerialized;
    CAmount nTotalAmount;

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), nTotalAmount(0) {}
};

//! Calculate statistics about the unspent transaction output set
static bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
{
    boost::scoped_ptr<CCoinsViewCursor> pcursor(view->Cursor());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        stats.nHeight = mapBlockIndex.find(stats.hashBlock)->second->nHeight;
    }
    ss << stats.hashBlock;
    CAmount nTotalAmount = 0;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        uint256 key;
        CCoins coins;
        if (pcursor->GetKey(key) && pcursor->GetValue(coins)) {
            stats.nTransactions++;
            for (unsigned int i=0; i<coins.vout.size(); i++) {
                const CTxOut &out = coins.vout[i];
                if (!out.IsNull()) {
                    stats.nTransactionOutputs++;
                    ss << VARINT(i+1);
                    ss << out;
                    nTotalAmount += out.nValue;
                }
            }
            stats.nSerializedSize += 32 + pcursor->GetValueSize();
            ss << VARINT(0);
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    stats.hashSerialized = ss.GetHash();
    stats.nTotalAmount = nTotalAmount;
    return true;
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"

            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("gettxoutsetinfo", "") + HelpExampleRpc("gettxoutsetinfo", ""));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (GetUTXOStats(pcoinsdbview.get(), stats)) {
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"

            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to included the mem pool\n"

            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in btc\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of ion addresses\n"
            "     \"ionaddress\"   	 	(string) ion address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nView the details\n" +
            HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("gettxout", "\"txid\", 1"));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip.get(), mempool);
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return NullUniValue;
    }
    if (n < 0 || (unsigned int)n >= coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    CBlockIndex* pindex = it->second;
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue verifychain(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "verifychain ( numblocks )\n"
            "\nVerifies blockchain database.\n"

            "\nArguments:\n"
            "1. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n"

            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"

            "\nExamples:\n" +
            HelpExampleCli("verifychain", "") + HelpExampleRpc("verifychain", ""));

    LOCK(cs_main);

    int nCheckLevel = 4;
    int nCheckDepth = GetArg("-checkblocks", 288);
    if (params.size() > 0)
        nCheckDepth = params[0].get_int();

    fVerifyingBlocks = true;
    bool fVerified = CVerifyDB().VerifyDB(pcoinsTip.get(), nCheckLevel, nCheckDepth);
    fVerifyingBlocks = false;

    return fVerified;
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int minVersion, CBlockIndex* pindex, int nRequired)
{
    int nFound = 0;
    CBlockIndex* pstart = pindex;
    for (int i = 0; i < Params().ToCheckBlockUpgradeMajority() && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("status", nFound >= nRequired));
    rv.push_back(Pair("found", nFound));
    rv.push_back(Pair("required", nRequired));
    rv.push_back(Pair("window", Params().ToCheckBlockUpgradeMajority()));
    return rv;
}
static UniValue SoftForkDesc(const std::string &name, int version, CBlockIndex* pindex)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("version", version));
    rv.push_back(Pair("enforce", SoftForkMajorityDesc(version, pindex, Params().EnforceBlockUpgradeMajority())));
    rv.push_back(Pair("reject", SoftForkMajorityDesc(version, pindex, Params().RejectBlockOutdatedMajority())));
    return rv;
}

UniValue getblockchaininfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"

            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
            "        \"enforce\": {           (object) progress toward enforcing the softfork rules for new-version blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "           \"found\": xx,        (numeric) number of blocks with the new version found\n"
            "           \"required\": xx,     (numeric) number of blocks required to trigger\n"
            "           \"window\": xx,       (numeric) maximum size of examined window of recent blocks\n"
            "        },\n"
            "        \"reject\": { ... }      (object) progress toward rejecting pre-softfork blocks (same fields as \"enforce\")\n"
            "     }, ...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockchaininfo", "") + HelpExampleRpc("getblockchaininfo", ""));

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("chain", Params().NetworkIDString()));
    obj.push_back(Pair("blocks", (int)chainActive.Height()));
    obj.push_back(Pair("headers", pindexBestHeader ? pindexBestHeader->nHeight : -1));
    obj.push_back(Pair("bestblockhash", chainActive.Tip()->GetBlockHash().GetHex()));
    obj.push_back(Pair("difficulty", (double)GetDifficulty()));
    obj.push_back(Pair("verificationprogress", Checkpoints::GuessVerificationProgress(chainActive.Tip())));
    obj.push_back(Pair("chainwork", chainActive.Tip()->nChainWork.GetHex()));
    CBlockIndex* tip = chainActive.Tip();
    UniValue softforks(UniValue::VARR);
    softforks.push_back(SoftForkDesc("bip65", 5, tip));
    obj.push_back(Pair("softforks",             softforks));
    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight {
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
            return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getchaintips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"

            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"

            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") + HelpExampleRpc("getchaintips", ""));

    LOCK(cs_main);

    /* Build up a list of chain tips.  We start with the list of all
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    for (const PAIRTYPE(const uint256, CBlockIndex*) & item : mapBlockIndex)
        setTips.insert(item.second);
    for (const PAIRTYPE(const uint256, CBlockIndex*) & item : mapBlockIndex) {
        const CBlockIndex* pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev);
    }

    // Always report the currently active tip.
    setTips.insert(chainActive.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", block->nHeight));
        obj.push_back(Pair("hash", block->phashBlock->GetHex()));

        const int branchLen = block->nHeight - chainActive.FindFork(block)->nHeight;
        obj.push_back(Pair("branchlen", branchLen));

        string status;
        if (chainActive.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (block->nChainTx == 0) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res;
}

UniValue getfeeinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getfeeinfo blocks\n"
            "\nReturns details of transaction fees over the last n blocks.\n"

            "\nArguments:\n"
            "1. blocks     (int, required) the number of blocks to get transaction data from\n"

            "\nResult:\n"
            "{\n"
            "  \"txcount\": xxxxx                (numeric) Current tx count\n"
            "  \"txbytes\": xxxxx                (numeric) Sum of all tx sizes\n"
            "  \"ttlfee\": xxxxx                 (numeric) Sum of all fees\n"
            "  \"feeperkb\": xxxxx               (numeric) Average fee per kb over the block range\n"
            "  \"rec_highpriorityfee_perkb\": xxxxx    (numeric) Recommended fee per kb to use for a high priority tx\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getfeeinfo", "5") + HelpExampleRpc("getfeeinfo", "5"));

    int nBlocks = params[0].get_int();
    int nBestHeight;
    {
        LOCK(cs_main);
        nBestHeight = chainActive.Height();
    }
    int nStartHeight = nBestHeight - nBlocks;
    if (nBlocks < 0 || nStartHeight <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid start height");

    UniValue newParams(UniValue::VARR);
    newParams.push_back(UniValue(nStartHeight));
    newParams.push_back(UniValue(nBlocks));
    newParams.push_back(UniValue(true));    // fFeeOnly

    return getblockindexstats(newParams, false);
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("size", (int64_t) mempool.size()));
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize()));
    //ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage()));

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"

            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx                (numeric) Current tx count\n"
            "  \"bytes\": xxxxx               (numeric) Sum of all tx sizes\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getmempoolinfo", "") + HelpExampleRpc("getmempoolinfo", ""));

    return mempoolInfoToJSON();
}

UniValue invalidateblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"

            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"

            "\nExamples:\n" +
            HelpExampleCli("invalidateblock", "\"blockhash\"") + HelpExampleRpc("invalidateblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        InvalidateBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"

            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"

            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") + HelpExampleRpc("reconsiderblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue findserial(const UniValue& params, bool fHelp)
{
    if(fHelp || params.size() != 1)
        throw runtime_error(
            "findserial \"serial\"\n"
            "\nSearches the zerocoin database for a zerocoin spend transaction that contains the specified serial\n"

            "\nArguments:\n"
            "1. serial   (string, required) the serial of a zerocoin spend to search for.\n"

            "\nResult:\n"
            "{\n"
            "  \"success\": true|false        (boolean) Whether the serial was found\n"
            "  \"txid\": \"xxx\"              (string) The transaction that contains the spent serial\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("findserial", "\"serial\"") + HelpExampleRpc("findserial", "\"serial\""));

    std::string strSerial = params[0].get_str();
    CBigNum bnSerial = 0;
    bnSerial.SetHex(strSerial);
    if (!bnSerial)
	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid serial");

    uint256 txid = 0;
    bool fSuccess = zerocoinDB->ReadCoinSpend(bnSerial, txid);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("success", fSuccess));
    ret.push_back(Pair("txid", txid.GetHex()));
    return ret;
}

UniValue getaccumulatorvalues(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccumulatorvalues \"height\"\n"
                    "\nReturns the accumulator values associated with a block height\n"

                    "\nArguments:\n"
                    "1. height   (numeric, required) the height of the checkpoint.\n"

                    "\nExamples:\n" +
            HelpExampleCli("getaccumulatorvalues", "\"height\"") + HelpExampleRpc("getaccumulatorvalues", "\"height\""));

    int nHeight = params[0].get_int();

    CBlockIndex* pindex = chainActive[nHeight];
    if (!pindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid block height");

    UniValue ret(UniValue::VARR);
    for (libzerocoin::CoinDenomination denom : libzerocoin::zerocoinDenomList) {
        CBigNum bnValue;
        if(!GetAccumulatorValueFromDB(pindex->nAccumulatorCheckpoint, denom, bnValue))
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to find value in database");

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair(std::to_string(denom), bnValue.GetHex()));
        ret.push_back(obj);
    }

    return ret;
}


UniValue getaccumulatorwitness(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "getaccumulatorwitness \"commitmentCoinValue, coinDenomination\"\n"
                "\nReturns the accumulator witness value associated with the coin\n"

                "\nArguments:\n"
                "1. coinValue             (string, required) the commitment value of the coin in HEX.\n"
                "2. coinDenomination      (numeric, required) the coin denomination.\n"

                "\nResult:\n"
                "{\n"
                "  \"Accumulator Value\": \"xxx\"  (string) Accumulator hex value\n"
                "  \"Denomination\": \"d\"         (integer) Accumulator denomination\n"
                "  \"Mints added\": \"d\"          (integer) Number of mints added to the accumulator\n"
                "  \"Witness Value\": \"xxx\"      (string) Witness hex value\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getaccumulatorwitness", "\"5fb87fb7bb638e83bfc14bcf33ac6f8064c9884dc72a4e652666abcf42cc47f9da0a7aca58076b0122a19b25629a6b6e7461f188baa7c00865b862cdb270d934873648aa12dd66e3242da40e4c17c78b70fded35e2d9c72933b455fadce9684586b1d48b10570d66feebe51ccebb1d98595217d06f41e66d5a0d9246d46ec3dd\" 5") + HelpExampleRpc("getaccumulatorwitness", "\"5fb87fb7bb638e83bfc14bcf33ac6f8064c9884dc72a4e652666abcf42cc47f9da0a7aca58076b0122a19b25629a6b6e7461f188baa7c00865b862cdb270d934873648aa12dd66e3242da40e4c17c78b70fded35e2d9c72933b455fadce9684586b1d48b10570d66feebe51ccebb1d98595217d06f41e66d5a0d9246d46ec3dd\", 5"));


    CBigNum coinValue;
    coinValue.SetHex(params[0].get_str());

    int d = params[1].get_int();
    libzerocoin::CoinDenomination denomination = libzerocoin::IntToZerocoinDenomination(d);
    libzerocoin::ZerocoinParams* zcparams = Params().Zerocoin_Params(false);

    // Public coin
    libzerocoin::PublicCoin pubCoin(zcparams, coinValue, denomination);

    //Compute Accumulator and Witness
    libzerocoin::Accumulator accumulator(zcparams, pubCoin.getDenomination());
    libzerocoin::AccumulatorWitness witness(zcparams, accumulator, pubCoin);
    string strFailReason = "";
    int nMintsAdded = 0;
    CZerocoinSpendReceipt receipt;

    if (!GenerateAccumulatorWitness(pubCoin, accumulator, witness, nMintsAdded, strFailReason)) {
        receipt.SetStatus(_(strFailReason.c_str()), XION_FAILED_ACCUMULATOR_INITIALIZATION);
        throw JSONRPCError(RPC_DATABASE_ERROR, receipt.GetStatusMessage());
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("Accumulator Value", accumulator.getValue().GetHex()));
    obj.push_back(Pair("Denomination", accumulator.getDenomination()));
    obj.push_back(Pair("Mints added",nMintsAdded));
    obj.push_back(Pair("Witness Value", witness.getValue().GetHex()));

    return obj;
}

void validaterange(const UniValue& params, int& heightStart, int& heightEnd, int minHeightStart)
{
    if (params.size() < 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not enough parameters in validaterange");
    }

    int nBestHeight;
    {
        LOCK(cs_main);
        nBestHeight = chainActive.Height();
    }

    heightStart = params[0].get_int();
    if (heightStart > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid starting block (%d). Out of range.", heightStart));
    }

    const int range = params[1].get_int();
    if (range < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range. Must be strictly positive.");
    }

    heightEnd = heightStart + range - 1;

    if (heightStart < minHeightStart && heightEnd >= minHeightStart) {
        heightStart = minHeightStart;
    }

    if (heightEnd > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid ending block (%d). Out of range.", heightEnd));
    }
}

UniValue getmintsinblocks(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 3)
        throw runtime_error(
                "getmintsinblocks height range coinDenomination\n"
                "\nReturns the number of mints of a certain denomination"
                "\noccurred in blocks [height, height+1, height+2, ..., height+range-1]\n"

                "\nArguments:\n"
                "1. height             (numeric, required) block height where the search starts.\n"
                "2. range              (numeric, required) number of blocks to include.\n"
                "3. coinDenomination   (numeric, required) coin denomination.\n"

                "\nResult:\n"
                "{\n"
                "  \"Starting block\": \"x\"           (integer) First counted block\n"
                "  \"Ending block\": \"x\"             (integer) Last counted block\n"
                "  \"Number of d-denom mints\": \"x\"  (integer) number of mints of the required d denomination\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getmintsinblocks", "1200000 1000 5") +
                HelpExampleRpc("getmintsinblocks", "1200000, 1000, 5"));

    int heightStart, heightEnd;
    validaterange(params, heightStart, heightEnd, Params().Zerocoin_StartHeight());

    int d = params[2].get_int();
    libzerocoin::CoinDenomination denom = libzerocoin::IntToZerocoinDenomination(d);
    if (denom == libzerocoin::CoinDenomination::ZQ_ERROR)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid denomination. Must be in {1, 5, 10, 50, 100, 500, 1000, 5000}");

    int num_of_mints = 0;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive[heightStart];

        while (true) {
            num_of_mints += count(pindex->vMintDenominationsInBlock.begin(), pindex->vMintDenominationsInBlock.end(), denom);
            if (pindex->nHeight < heightEnd) {
                pindex = chainActive.Next(pindex);
            } else {
                break;
            }
        }
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("Starting block", heightStart));
    obj.push_back(Pair("Ending block", heightEnd-1));
    obj.push_back(Pair("Number of "+ std::to_string(d) +"-denom mints", num_of_mints));

    return obj;
}


UniValue getserials(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "getserials height range ( fVerbose )\n"
            "\nLook the inputs of any tx in a range of blocks and returns the serial numbers for any coinspend.\n"

            "\nArguments:\n"
            "1. starting_height   (numeric, required) the height of the first block to check\n"
            "2. range             (numeric, required) the amount of blocks to check\n"
            "3. fVerbose          (boolean, optional, default=False) return verbose output\n"

            "\nExamples:\n" +
            HelpExampleCli("getserials", "1254000 1000") +
            HelpExampleRpc("getserials", "1254000, 1000"));

    int heightStart, heightEnd;
    validaterange(params, heightStart, heightEnd, Params().Zerocoin_StartHeight());

    bool fVerbose = false;
    if (params.size() > 2) {
        fVerbose = params[2].get_bool();
    }

    CBlockIndex* pblockindex = nullptr;
    {
        LOCK(cs_main);
        pblockindex = chainActive[heightStart];
    }

    if (!pblockindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid block height");

    UniValue serialsObj(UniValue::VOBJ);    // for fVerbose
    UniValue serialsArr(UniValue::VARR);

    while (true) {
        CBlock block;
        if (!ReadBlockFromDisk(block, pblockindex))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

        // loop through each tx in the block
        for (const CTransaction& tx : block.vtx) {
            std::string txid = tx.GetHash().GetHex();
            // collect the destination (first output) if fVerbose
            std::string spentTo = "";
            if (fVerbose) {
                if (tx.vout[0].IsZerocoinMint()) {
                    spentTo = "Zerocoin Mint";
                } else if (tx.vout[0].IsEmpty()) {
                    spentTo = "Zerocoin Stake";
                } else {
                    txnouttype type;
                    vector<CTxDestination> addresses;
                    int nRequired;
                    if (!ExtractDestinations(tx.vout[0].scriptPubKey, type, addresses, nRequired)) {
                        spentTo = strprintf("type: %d", GetTxnOutputType(type));
                    } else {
                        spentTo = CBitcoinAddress(addresses[0]).ToString();
                    }
                }
            }
            // loop through each input
            for (const CTxIn& txin : tx.vin) {
                bool isPublicSpend =  txin.IsZerocoinPublicSpend();
                if (txin.IsZerocoinSpend() || isPublicSpend) {
                    std::string serial_str;
                    int denom;
                    if (isPublicSpend) {
                        CTxOut prevOut;
                        CValidationState state;
                        if(!GetOutput(txin.prevout.hash, txin.prevout.n, state, prevOut)){
                            throw JSONRPCError(RPC_INTERNAL_ERROR, "public zerocoin spend prev output not found");
                        }
                        libzerocoin::ZerocoinParams *params = Params().Zerocoin_Params(false);
                        PublicCoinSpend publicSpend(params);
                        if (!XIONModule::parseCoinSpend(txin, tx, prevOut, publicSpend)) {
                            throw JSONRPCError(RPC_INTERNAL_ERROR, "public zerocoin spend parse failed");
                        }
                        serial_str = publicSpend.getCoinSerialNumber().ToString(16);
                        denom = libzerocoin::ZerocoinDenominationToInt(publicSpend.getDenomination());
                    } else {
                        libzerocoin::CoinSpend spend = TxInToZerocoinSpend(txin);
                        serial_str = spend.getCoinSerialNumber().ToString(16);
                        denom = libzerocoin::ZerocoinDenominationToInt(spend.getDenomination());
                    }
                    if (!fVerbose) {
                        serialsArr.push_back(serial_str);
                    } else {
                        UniValue s(UniValue::VOBJ);
                        s.push_back(Pair("serial", serial_str));
                        s.push_back(Pair("denom", denom));
                        s.push_back(Pair("bitsize", (int)serial_str.size()*4));
                        s.push_back(Pair("spentTo", spentTo));
                        s.push_back(Pair("txid", txid));
                        s.push_back(Pair("blocknum", pblockindex->nHeight));
                        s.push_back(Pair("blocktime", block.GetBlockTime()));
                        serialsArr.push_back(s);
                    }
                }

            } // end for vin in tx
        } // end for tx in block

        if (pblockindex->nHeight < heightEnd) {
            LOCK(cs_main);
            pblockindex = chainActive.Next(pblockindex);
        } else {
            break;
        }

    } // end for blocks

    return serialsArr;

}

UniValue getaccumulatorcheckpoints(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccumulatorcheckpoints \"height\"\n"
                    "\nReturns the calculated accumulator values associated with a block height\n"

                    "\nArguments:\n"
                    "1. height   (numeric, required) the height of the checkpoint.\n"

                    "\nExamples:\n" +
            HelpExampleCli("getaccumulatorcheckpoints", "\"height\"") + HelpExampleRpc("generateaccumulatorvalues", "\"height\""));

    int nHeight = params[0].get_int();

    CBlockIndex* pindex = chainActive[nHeight];
    if (!pindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid block height");

    uint256 nCheckpointCalculated = 0;

    AccumulatorMap mapAccumulators(Params().Zerocoin_Params(false));

    if (!CalculateAccumulatorCheckpointWithoutDB(nHeight, nCheckpointCalculated, mapAccumulators))
        return error("%s : failed to calculate accumulator checkpoint", __func__);

    UniValue ret(UniValue::VARR);
    UniValue obj(UniValue::VOBJ);

    obj.push_back(Pair("height", nHeight));
    for (libzerocoin::CoinDenomination denom : libzerocoin::zerocoinDenomList) {
        CBigNum bnValue;

        bnValue = mapAccumulators.GetValue(denom);
        obj.push_back(Pair(std::to_string(denom), bnValue.GetHex()));
    }
    ret.push_back(obj);

    return ret;
}
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results) {
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        uint256 key;
        CCoins coins;
        if (!cursor->GetKey(key) || !cursor->GetValue(coins)) return false;
        for (unsigned int i=0; i<coins.vout.size(); i++) {
            const CTxOut &out = coins.vout[i];
            if (!out.IsNull()) {
                if (++count % 8192 == 0) {
                    boost::this_thread::interruption_point();
                    if (should_abort) {
                        // allow to abort the scan via the abort reference
                        return false;
                    }
                }
                if (count % 256 == 0) {
                    // update progress reference every 256 item
                    uint32_t high = 0x100 * *key.begin() + *(key.begin() + 1);
                    scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
                }
                if (needles.count(out.scriptPubKey)) {
                    out_results.emplace(COutPoint(key, i), Coin(coins, i));
                }
            }
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}

//! Search for a given set of pubkey scripts
bool FindTokenGroupID(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const CTokenGroupID& needle, std::map<COutPoint, Coin>& out_results) {
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        uint256 key;
        CCoins coins;
        if (!cursor->GetKey(key) || !cursor->GetValue(coins)) return false;
        for (unsigned int i=0; i<coins.vout.size(); i++) {
            const CTxOut &out = coins.vout[i];
            if (!out.IsNull()) {
                if (++count % 8192 == 0) {
                    boost::this_thread::interruption_point();
                    if (should_abort) {
                        // allow to abort the scan via the abort reference
                        return false;
                    }
                }
                if (count % 256 == 0) {
                    // update progress reference every 256 item
                    uint32_t high = 0x100 * *key.begin() + *(key.begin() + 1);
                    scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
                }
                CTokenGroupInfo tokenGrp(out.scriptPubKey);
                if ((tokenGrp.associatedGroup != NoGroup) && !tokenGrp.isAuthority() && tokenGrp.associatedGroup == needle) // must be sitting in any group address
                {
                    out_results.emplace(COutPoint(key, i), Coin(coins, i));
                }

            }
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::mutex g_utxosetscan;
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve;
public:
    explicit CoinsViewScanReserver() : m_could_reserve(false) {}

    bool reserve() {
        assert (!m_could_reserve);
        std::lock_guard<std::mutex> lock(g_utxosetscan);
        if (g_scan_in_progress) {
            return false;
        }
        g_scan_in_progress = true;
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            std::lock_guard<std::mutex> lock(g_utxosetscan);
            g_scan_in_progress = false;
        }
    }
};

static const char *g_default_scantxoutset_script_types[] = { "P2PKH", "P2SH_P2WPKH", "P2WPKH" };

enum class OutputScriptType {
    UNKNOWN,
    P2PK,
    P2PKH,
    P2SH_P2WPKH,
    P2WPKH
};

static inline OutputScriptType GetOutputScriptTypeFromString(const std::string& outputtype)
{
    if (outputtype == "P2PK") return OutputScriptType::P2PK;
    else if (outputtype == "P2PKH") return OutputScriptType::P2PKH;
    else return OutputScriptType::UNKNOWN;
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputScriptType type)
{
    switch (type) {
    case OutputScriptType::P2PKH: return key.GetID();
    default: assert(false);
    }
}

UniValue scantxoutset(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "scantxoutset <action> ( <scanobjects> )\n"
            "\nScans the unspent transaction output set for possible entries that matches common scripts of given public keys.\n"
            "Using addresses as scanobjects will _not_ detect unspent P2PK txouts\n"
            "\nArguments:\n"
            "1. \"action\"                       (string, required) The action to execute\n"
            "                                      \"start\" for starting a scan\n"
            "                                      \"abort\" for aborting the current scan (returns true when abort was successful)\n"
            "                                      \"status\" for progress report (in %) of the current scan\n"
            "2. \"scanobjects\"                  (array, optional) Array of scan objects (only one object type per scan object allowed)\n"
            "      [\n"
            "        { \"address\" : \"<address>\" },       (string, optional) Bitcoin address\n"
            "        { \"script\"  : \"<scriptPubKey>\" },  (string, optional) HEX encoded script (scriptPubKey)\n"
            "        { \"pubkey\"  :                      (object, optional) Public key\n"
            "          {\n"
            "            \"pubkey\" : \"<pubkey\">,         (string, required) HEX encoded public key\n"
            "            \"script_types\" : [ ... ],      (array, optional) Array of script-types to derive from the pubkey (possible values: \"P2PK\", \"P2PKH\", \"P2SH-P2WPKH\", \"P2WPKH\")\n"
            "          }\n"
            "        },\n"
            "      ]\n"
            "\nResult:\n"
            "{\n"
            "  \"unspents\": [\n"
            "    {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id\n"
            "    \"vout\": n,                    (numeric) the vout value\n"
            "    \"scriptPubKey\" : \"script\",    (string) the script key\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount in ION of the unspent output\n"
            "    \"height\" : n,                 (numeric) Height of the unspent transaction output\n"
            "   }\n"
            "   ,...], \n"
            " \"total_amount\" : x.xxx,          (numeric) The total amount of all found unspent outputs in ION\n"
            "]\n"
        );

    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VARR});

    UniValue result(UniValue::VOBJ);
    if (params[0].get_str() == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        result.pushKV("progress", g_scan_progress);
        return result;
    } else if (params[0].get_str() == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (params[0].get_str() == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        std::set<CScript> needles;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : params[1].get_array().getValues()) {
            if (!scanobject.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid scan object");
            }
            UniValue address_uni = find_value(scanobject, "address");
            UniValue pubkey_uni  = find_value(scanobject, "pubkey");
            UniValue script_uni  = find_value(scanobject, "script");

            // make sure only one object type is present
            if (1 != !address_uni.isNull() + !pubkey_uni.isNull() + !script_uni.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only one object type is allowed per scan object");
            } else if (!address_uni.isNull() && !address_uni.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Scanobject \"address\" must contain a single string as value");
            } else if (!pubkey_uni.isNull() && !pubkey_uni.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Scanobject \"pubkey\" must contain an object as value");
            } else if (!script_uni.isNull() && !script_uni.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Scanobject \"script\" must contain a single string as value");
            } else if (address_uni.isStr()) {
                // type: address
                // decode destination and derive the scriptPubKey
                // add the script to the scan containers
                CTxDestination dest = DecodeDestination(address_uni.get_str());
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
                }
                CScript script = GetScriptForDestination(dest);
                assert(!script.empty());
                needles.insert(script);
            } else if (pubkey_uni.isObject()) {
                // type: pubkey
                // derive script(s) according to the script_type parameter
                UniValue script_types_uni = find_value(pubkey_uni, "script_types");
                UniValue pubkeydata_uni = find_value(pubkey_uni, "pubkey");

                // check the script types and use the default if not provided
                if (!script_types_uni.isNull() && !script_types_uni.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "script_types must be an array");
                } else if (script_types_uni.isNull()) {
                    // use the default script types
                    script_types_uni = UniValue(UniValue::VARR);
                    for (const char *t : g_default_scantxoutset_script_types) {
                        script_types_uni.push_back(t);
                    }
                }

                // check the acctual pubkey
                if (!pubkeydata_uni.isStr() || !IsHex(pubkeydata_uni.get_str())) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Public key must be hex encoded");
                }
                CPubKey pubkey(ParseHexV(pubkeydata_uni, "pubkey"));
                if (!pubkey.IsFullyValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key");
                }

                // loop through the script types and derive the script
                for (const UniValue& script_type_uni : script_types_uni.get_array().getValues()) {
                    OutputScriptType script_type = GetOutputScriptTypeFromString(script_type_uni.get_str());
                    if (script_type == OutputScriptType::UNKNOWN) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid script type");
                    CScript script;
                    if (script_type == OutputScriptType::P2PK) {
                        // support legacy P2PK scripts
                        script << ToByteVector(pubkey) << OP_CHECKSIG;
                    } else {
                        script = GetScriptForDestination(GetDestinationForKey(pubkey, script_type));
                    }
                    assert(!script.empty());
                    needles.insert(script);
                }
            } else if (script_uni.isStr()) {
                // type: script
                // check and add the script to the scan containers (needles array)
                CScript script(ParseHexV(script_uni, "script"));
                // TODO: check script: max length, has OP, is unspenable etc.
                needles.insert(script);
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        g_scan_progress = 0;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        {
            LOCK(cs_main);
            FlushStateToDisk();
            pcursor = std::unique_ptr<CCoinsViewCursor>(pcoinsdbview->Cursor());
            assert(pcursor);
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins);
        result.pushKV("success", res);
        result.pushKV("searched_items", count);

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            input_txos.push_back(txo);
            total_in += txo.nValue;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", (int32_t)outpoint.n);
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey.begin(), txo.scriptPubKey.end()));
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("height", (int32_t)coin.nHeight);

            unspents.push_back(unspent);
        }
        result.pushKV("unspents", unspents);
        result.pushKV("total_amount", ValueFromAmount(total_in));
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid command");
    }
    return result;
}

UniValue scantokens(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "scantokens <action> ( <scanobjects> )\n"
            "\nScans the unspent transaction output set for possible entries that belong to a specified token group.\n"
            "\nArguments:\n"
            "1. \"action\"                     (string, required) The action to execute\n"
            "                                      \"start\" for starting a scan\n"
            "                                      \"abort\" for aborting the current scan (returns true when abort was successful)\n"
            "                                      \"status\" for progress report (in %) of the current scan\n"
            "2. \"tokenGroupID\"               (string, optional) Token group identifier\n"
            "\n"
            "\nResult:\n"
            "{\n"
            "  \"unspents\": [\n"
            "    {\n"
            "    \"txid\" : \"transactionid\",   (string) The transaction id\n"
            "    \"vout\" : n,                 (numeric) the vout value\n"
            "    \"address\" : \"address\",      (string) the address that received the tokens\n"
            "    \"scriptPubKey\" : \"script\",  (string) the script key\n"
            "    \"ION_amount\" : x.xxx,       (numeric) The total amount in ION of the unspent output\n"
            "    \"token_amount\" : xxx,       (numeric) The total token amount of the unspent output\n"
            "    \"height\" : n,               (numeric) Height of the unspent transaction output\n"
            "   }\n"
            "   ,...], \n"
            " \"total_amount\" : xxx,          (numeric) The total token amount of all found unspent outputs\n"
            "]\n"
        );

    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VSTR});

    UniValue result(UniValue::VOBJ);
    if (params[0].get_str() == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        result.pushKV("progress", g_scan_progress);
        return result;
    } else if (params[0].get_str() == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (params[0].get_str() == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        CAmount total_in = 0;

        if (!params[1].isStr()){
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No token group ID specified");
        }

        CTokenGroupID needle = GetTokenGroup(params[1].get_str());
        if (!needle.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid group specified");
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        g_scan_progress = 0;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        {
            LOCK(cs_main);
            FlushStateToDisk();
            pcursor = std::unique_ptr<CCoinsViewCursor>(pcoinsdbview->Cursor());
            assert(pcursor);
        }
        bool res = FindTokenGroupID(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needle, coins);
        result.pushKV("success", res);
        result.pushKV("searched_items", count);

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            const CTokenGroupInfo& tokenGroupInfo = CTokenGroupInfo(txo.scriptPubKey);
            CTxDestination dest;
            ExtractDestination(txo.scriptPubKey, dest);

            input_txos.push_back(txo);
            total_in += tokenGroupInfo.quantity;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", (int32_t)outpoint.n);
            if (IsValidDestination(dest)) {
                unspent.push_back(Pair("address", EncodeDestination(dest)));
            }
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey.begin(), txo.scriptPubKey.end()));
            unspent.pushKV("ION_Amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("token_Amount", tokenGroupInfo.quantity);
            unspent.pushKV("height", (int32_t)coin.nHeight);

            unspents.push_back(unspent);
        }

        result.pushKV("unspents", unspents);
        result.pushKV("total_amount", total_in);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid command");
    }
    return result;
}

UniValue getblockindexstats(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
                "getblockindexstats height range ( fFeeOnly )\n"
                "\nReturns aggregated BlockIndex data for blocks "
                "\n[height, height+1, height+2, ..., height+range-1]\n"

                "\nArguments:\n"
                "1. height             (numeric, required) block height where the search starts.\n"
                "2. range              (numeric, required) number of blocks to include.\n"
                "3. fFeeOnly           (boolean, optional, default=False) return only fee info.\n"

                "\nResult:\n"
                "{\n"
                "  \"first_block\": \"x\"            (integer) First counted block\n"
                "  \"last_block\": \"x\"             (integer) Last counted block\n"
                "  \"txcount\": xxxxx                (numeric) tx count (excluding coinbase/coinstake)\n"
                "  \"txcount_all\": xxxxx            (numeric) tx count (including coinbase/coinstake)\n"
                "  \"mintcount\": {              [if fFeeOnly=False]\n"
                "        \"denom_1\": xxxx           (numeric) number of mints of denom_1 occurred over the block range\n"
                "        \"denom_5\": xxxx           (numeric) number of mints of denom_5 occurred over the block range\n"
                "         ...                    ... number of mints of other denominations: ..., 10, 50, 100, 500, 1000, 5000\n"
                "  }\n"
                "  \"spendcount\": {             [if fFeeOnly=False]\n"
                "        \"denom_1\": xxxx           (numeric) number of spends of denom_1 occurred over the block range\n"
                "        \"denom_5\": xxxx           (numeric) number of spends of denom_5 occurred over the block range\n"
                "         ...                    ... number of spends of other denominations: ..., 10, 50, 100, 500, 1000, 5000\n"
                "  }\n"
                "  \"pubspendcount\": {             [if fFeeOnly=False]\n"
                "        \"denom_1\": xxxx           (numeric) number of PUBLIC spends of denom_1 occurred over the block range\n"
                "        \"denom_5\": xxxx           (numeric) number of PUBLIC spends of denom_5 occurred over the block range\n"
                "         ...                    ... number of PUBLIC spends of other denominations: ..., 10, 50, 100, 500, 1000, 5000\n"
                "  }\n"
                "  \"txbytes\": xxxxx                (numeric) Sum of the size of all txes (xION excluded) over block range\n"
                "  \"ttlfee\": xxxxx                 (numeric) Sum of the fee amount of all txes (xION mints excluded) over block range\n"
                "  \"ttlfee_all\": xxxxx             (numeric) Sum of the fee amount of all txes (xION mints included) over block range\n"
                "  \"feeperkb\": xxxxx               (numeric) Average fee per kb (excluding zc txes)\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getblockindexstats", "1200000 1000") +
                HelpExampleRpc("getblockindexstats", "1200000, 1000"));

    int heightStart, heightEnd;
    validaterange(params, heightStart, heightEnd);
    // return object
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("Starting block", heightStart));
    ret.push_back(Pair("Ending block", heightEnd));

    bool fFeeOnly = false;
    if (params.size() > 2) {
        fFeeOnly = params[2].get_bool();
    }

    CAmount nFees = 0;
    CAmount nFees_all = 0;
    int64_t nBytes = 0;
    int64_t nTxCount = 0;
    int64_t nTxCount_all = 0;

    std::map<libzerocoin::CoinDenomination, int64_t> mapMintCount;
    std::map<libzerocoin::CoinDenomination, int64_t> mapSpendCount;
    std::map<libzerocoin::CoinDenomination, int64_t> mapPublicSpendCount;
    for (auto& denom : libzerocoin::zerocoinDenomList) {
        mapMintCount.insert(make_pair(denom, 0));
        mapSpendCount.insert(make_pair(denom, 0));
        mapPublicSpendCount.insert(make_pair(denom, 0));
    }

    CBlockIndex* pindex = nullptr;
    {
        LOCK(cs_main);
        pindex = chainActive[heightStart];
    }

    if (!pindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid block height");

    while (true) {
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read block from disk");
        }

        CAmount nValueIn = 0;
        CAmount nValueOut = 0;
        const int ntx = block.vtx.size();
        nTxCount_all += ntx;
        nTxCount = block.IsProofOfStake() ? nTxCount + ntx - 2 : nTxCount + ntx - 1;

        // loop through each tx in block and save size and fee
        for (const CTransaction& tx : block.vtx) {
            if (tx.IsCoinBase() || (tx.IsCoinStake() && !tx.HasZerocoinSpendInputs()))
                continue;

            // fetch input value from prevouts and count spends
            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                if (tx.vin[j].IsZerocoinSpend()) {
                    if (!fFeeOnly)
                        mapSpendCount[libzerocoin::IntToZerocoinDenomination(tx.vin[j].nSequence)]++;
                    continue;
                }
                if (tx.vin[j].IsZerocoinPublicSpend()) {
                    if (!fFeeOnly)
                        mapPublicSpendCount[libzerocoin::IntToZerocoinDenomination(tx.vin[j].nSequence)]++;
                    continue;
                }

                COutPoint prevout = tx.vin[j].prevout;
                CTransaction txPrev;
                uint256 hashBlock;
                if(!GetTransaction(prevout.hash, txPrev, hashBlock, true))
                    throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read tx from disk");
                nValueIn += txPrev.vout[prevout.n].nValue;
            }

            // zc spends have no fee
            if (tx.HasZerocoinSpendInputs())
                continue;

            // sum output values in nValueOut
            for (unsigned int j = 0; j < tx.vout.size(); j++) {
                nValueOut += tx.vout[j].nValue;
            }

            // update sums
            nFees_all += nValueIn - nValueOut;
            if (!tx.HasZerocoinMintOutputs()) {
                nFees += nValueIn - nValueOut;
                nBytes += tx.GetSerializeSize(SER_NETWORK, CLIENT_VERSION);
            }
        }

        // add mints to map
        if (!fFeeOnly) {
            for (auto& denom : libzerocoin::zerocoinDenomList) {
                mapMintCount[denom] += count(pindex->vMintDenominationsInBlock.begin(), pindex->vMintDenominationsInBlock.end(), denom);
            }
        }

        if (pindex->nHeight < heightEnd) {
            LOCK(cs_main);
            pindex = chainActive.Next(pindex);
        } else {
            break;
        }
    }

    // get fee rate
    CFeeRate nFeeRate = CFeeRate(nFees, nBytes);

    // return UniValue object
    ret.push_back(Pair("txcount", (int64_t)nTxCount));
    ret.push_back(Pair("txcount_all", (int64_t)nTxCount_all));
    if (!fFeeOnly) {
        UniValue mint_obj(UniValue::VOBJ);
        UniValue spend_obj(UniValue::VOBJ);
        UniValue pubspend_obj(UniValue::VOBJ);
        for (auto& denom : libzerocoin::zerocoinDenomList) {
            mint_obj.push_back(Pair(strprintf("denom_%d", ZerocoinDenominationToInt(denom)), mapMintCount[denom]));
            spend_obj.push_back(Pair(strprintf("denom_%d", ZerocoinDenominationToInt(denom)), mapSpendCount[denom]));
            pubspend_obj.push_back(Pair(strprintf("denom_%d", ZerocoinDenominationToInt(denom)), mapPublicSpendCount[denom]));
        }
        ret.push_back(Pair("mintcount", mint_obj));
        ret.push_back(Pair("spendcount", spend_obj));
        ret.push_back(Pair("publicspendcount", pubspend_obj));

    }
    ret.push_back(Pair("txbytes", (int64_t)nBytes));
    ret.push_back(Pair("ttlfee", FormatMoney(nFees)));
    ret.push_back(Pair("ttlfee_all", FormatMoney(nFees_all)));
    ret.push_back(Pair("feeperkb", FormatMoney(nFeeRate.GetFeePerK())));

    return ret;
}
