// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* clang-format off */
// must be first for windows
#include "compat.h"

/* clang-format on */
#include "base58.h"
#include "random.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"

#include <openssl/rand.h>
#include <string>
#include <vector>

static bool sigInited = false;

// stop the logging
int LogPrintStr(const std::string &str) { return str.size(); }

// helper functions
namespace
{
CKey LoadKey(unsigned char *src)
{
    CKey secret;
    secret.Set(src, src + 32, true);
    return secret;
}
}

/** Return random bytes from cryptographically acceptable random sources */
extern "C" int RandomBytes(unsigned char *buf, int num)
{
    if (RAND_bytes(buf, num) != 1)
    {
        memset(buf, 0, num);
        return 0;
    }
    return num;
}

/** Given a private key, return its corresponding public key */
extern "C" int GetPubKey(unsigned char *keyData, unsigned char *result, unsigned int resultLen)
{
    if (!sigInited)
    {
        sigInited = true;
        ECC_Start();
    }

    CKey key = LoadKey(keyData);
    CPubKey pubkey = key.GetPubKey();
    unsigned int size = pubkey.size();
    if (size > resultLen)
        return 0;
    std::copy(pubkey.begin(), pubkey.end(), result);
    return size;
}


/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
*/
extern "C" int SignTx(unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    uint32_t nHashType,
    unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen)
{
    if (!sigInited)
    {
        sigInited = true;
        ECC_Start();
    }

    CTransaction tx;
    result[0] = 0;

    CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        ssData >> tx;
    }
    catch (const std::exception &)
    {
        return 0;
    }

    if (inputIdx >= tx.vin.size())
        return 0;

    CScript priorScript(prevoutScript, prevoutScript + priorScriptLen);
    CKey key = LoadKey(keyData);

    size_t nHashedOut = 0;
    uint256 sighash = SignatureHash(priorScript, tx, inputIdx, nHashType);
    std::vector<unsigned char> sig;
    if (!key.Sign(sighash, sig))
    {
        return 0;
    }
    sig.push_back((unsigned char)nHashType);
    unsigned int sigSize = sig.size();
    if (sigSize > resultLen)
        return 0;
    std::copy(sig.begin(), sig.end(), result);
    return sigSize;
}
