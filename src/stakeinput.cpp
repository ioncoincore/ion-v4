// Copyright (c) 2017-2018 The PIVX developers
// Copyright (c) 2018-2019 The Ion developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xion/accumulators.h"
#include "chain.h"
#include "xion/deterministicmint.h"
#include "main.h"
#include "stakeinput.h"
#include "wallet/wallet.h"

CXIonStake::CXIonStake(const libzerocoin::CoinSpend& spend)
{
    this->nChecksum = spend.getAccumulatorChecksum();
    this->denom = spend.getDenomination();
    uint256 nSerial = spend.getCoinSerialNumber().getuint256();
    this->hashSerial = Hash(nSerial.begin(), nSerial.end());
    fMint = false;
}

int CXIonStake::GetChecksumHeightFromMint()
{
    int nHeightChecksum = chainActive.Height() - Params().Zerocoin_RequiredStakeDepth();

    //Need to return the first occurance of this checksum in order for the validation process to identify a specific
    //block height
    uint32_t nChecksum = 0;
    nChecksum = ParseChecksum(chainActive[nHeightChecksum]->nAccumulatorCheckpoint, denom);
    return GetChecksumHeight(nChecksum, denom);
}

int CXIonStake::GetChecksumHeightFromSpend()
{
    return GetChecksumHeight(nChecksum, denom);
}

uint32_t CXIonStake::GetChecksum()
{
    return nChecksum;
}

// The xION block index is the first appearance of the accumulator checksum that was used in the spend
// note that this also means when staking that this checksum should be from a block that is beyond 60 minutes old and
// 100 blocks deep.
CBlockIndex* CXIonStake::GetIndexFrom()
{
    if (pindexFrom)
        return pindexFrom;

    int nHeightChecksum = 0;

    if (fMint)
        nHeightChecksum = GetChecksumHeightFromMint();
    else
        nHeightChecksum = GetChecksumHeightFromSpend();

    if (nHeightChecksum < Params().Zerocoin_StartHeight() || nHeightChecksum > chainActive.Height()) {
        pindexFrom = nullptr;
    } else {
        //note that this will be a nullptr if the height DNE
        pindexFrom = chainActive[nHeightChecksum];
    }

    return pindexFrom;
}

CAmount CXIonStake::GetValue()
{
    return denom * COIN;
}

//Use the first accumulator checkpoint that occurs 60 minutes after the block being staked from
// In case of regtest, next accumulator of 60 blocks after the block being staked from
bool CXIonStake::GetModifier(uint64_t& nStakeModifier)
{
    CBlockIndex* pindex = GetIndexFrom();
    if (!pindex)
        return error("%s: failed to get index from", __func__);

    if(Params().NetworkID() == CBaseChainParams::REGTEST) {
        // Stake modifier is fixed for now, move it to 60 blocks after this pindex in the future..
        nStakeModifier = pindexFrom->nStakeModifier;
        return true;
    }

    int64_t nTimeBlockFrom = pindex->GetBlockTime();
    while (true) {
        if (pindex->GetBlockTime() - nTimeBlockFrom > 60 * 60) {
            nStakeModifier = pindex->nAccumulatorCheckpoint.Get64();
            return true;
        }

        if (pindex->nHeight + 1 <= chainActive.Height())
            pindex = chainActive.Next(pindex);
        else
            return false;
    }
}

CDataStream CXIonStake::GetUniqueness()
{
    //The unique identifier for a xION is a hash of the serial
    CDataStream ss(SER_GETHASH, 0);
    ss << hashSerial;
    return ss;
}

bool CXIonStake::CreateTxIn(CWallet* pwallet, CTxIn& txIn, uint256 hashTxOut)
{
    CBlockIndex* pindexCheckpoint = GetIndexFrom();
    if (!pindexCheckpoint)
        return error("%s: failed to find checkpoint block index", __func__);

    CZerocoinMint mint;
    if (!pwallet->GetMintFromStakeHash(hashSerial, mint))
        return error("%s: failed to fetch mint associated with serial hash %s", __func__, hashSerial.GetHex());

    if (libzerocoin::ExtractVersionFromSerial(mint.GetSerialNumber()) < 2)
        return error("%s: serial extract is less than v2", __func__);

    CZerocoinSpendReceipt receipt;
    if (!pwallet->MintToTxIn(mint, hashTxOut, txIn, receipt, libzerocoin::SpendType::STAKE, pindexCheckpoint))
        return error("%s", receipt.GetStatusMessage());

    return true;
}

bool CXIonStake::CreateTxOuts(CWallet* pwallet, std::vector<CTxOut>& vout, CAmount nTotal)
{
    //Create an output returning the xION that was staked
    CTxOut outReward;
    libzerocoin::CoinDenomination denomStaked = libzerocoin::AmountToZerocoinDenomination(this->GetValue());
    CDeterministicMint dMint;
    if (!pwallet->CreateXIONOutPut(denomStaked, outReward, dMint))
        return error("%s: failed to create xION output", __func__);
    vout.emplace_back(outReward);

    //Add new staked denom to our wallet
    if (!pwallet->DatabaseMint(dMint))
        return error("%s: failed to database the staked xION", __func__);

    CAmount toMint = (nTotal - this->GetValue()) / 2;
    CAmount nRemaining = 0;
    while (toMint >= 1 * COIN) {
        libzerocoin::CoinDenomination denomination = libzerocoin::AmountToClosestDenomination(toMint, nRemaining);

        if (denomination == libzerocoin::ZQ_ERROR)
            return error("%s: failed to create xION output", __func__);

        CAmount nValueNewMint = libzerocoin::ZerocoinDenominationToAmount(denomination);
        toMint -= nValueNewMint;

        CTxOut out;
        CDeterministicMint dMintReward;
        if (!pwallet->CreateXIONOutPut(denomination, out, dMintReward))
            return error("%s: failed to create xION output", __func__);
        vout.emplace_back(out);

        if (!pwallet->DatabaseMint(dMintReward))
            return error("%s: failed to database mint reward", __func__);
    }

    return true;
}

bool CXIonStake::GetTxFrom(CTransaction& tx)
{
    return false;
}

bool CXIonStake::MarkSpent(CWallet *pwallet, const uint256& txid)
{
    CxIONTracker* xionTracker = pwallet->xionTracker.get();
    CMintMeta meta;
    if (!xionTracker->GetMetaFromStakeHash(hashSerial, meta))
        return error("%s: tracker does not have serialhash", __func__);

    xionTracker->SetPubcoinUsed(meta.hashPubcoin, txid);
    return true;
}

//!ION Stake
bool CIonStake::SetInput(CTransaction txPrev, unsigned int n)
{
    this->txFrom = txPrev;
    this->nPosition = n;
    return true;
}

bool CIonStake::GetTxFrom(CTransaction& tx)
{
    tx = txFrom;
    return true;
}

bool CIonStake::CreateTxIn(CWallet* pwallet, CTxIn& txIn, uint256 hashTxOut)
{
    txIn = CTxIn(txFrom.GetHash(), nPosition);
    return true;
}

CAmount CIonStake::GetValue()
{
    return txFrom.vout[nPosition].nValue;
}

bool CIonStake::CreateTxOuts(CWallet* pwallet, std::vector<CTxOut>& vout, CAmount nTotal)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKeyKernel = txFrom.vout[nPosition].scriptPubKey;
    if (!Solver(scriptPubKeyKernel, whichType, vSolutions)) {
        LogPrintf("CreateCoinStake : failed to parse kernel\n");
        return false;
    }

    if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH)
        return false; // only support pay to public key and pay to address

    CScript scriptPubKey;
    if (whichType == TX_PUBKEYHASH) // pay to address type
    {
        //convert to pay to public key type
        CKey key;
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        if (!pwallet->GetKey(keyID, key))
            return false;

        scriptPubKey << key.GetPubKey() << OP_CHECKSIG;
    } else
        scriptPubKey = scriptPubKeyKernel;

    vout.emplace_back(CTxOut(0, scriptPubKey));

    // Calculate if we need to split the output
    if (nTotal / 2 > (CAmount)(pwallet->nStakeSplitThreshold * COIN))
        vout.emplace_back(CTxOut(0, scriptPubKey));

    return true;
}

bool CIonStake::GetModifier(uint64_t& nStakeModifier)
{
/*
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;
    GetIndexFrom();
    if (!pindexFrom)
        return error("%s: failed to get index from", __func__);

    if (pindexFrom->nHeight >= Params().DGWStartHeight()) {
        if (!GetKernelStakeModifier(pindexFrom->GetBlockHash(), nStakeModifier, nStakeModifierHeight, nStakeModifierTime, false))
            return error("CheckStakeKernelHash(): failed to get kernel stake modifier \n");
    } else if (pindexFrom->nHeight < Params().DGWStartHeight()) {
        if (!GetKernelStakeModifierPreDGW(pindexFrom->GetBlockHash(), nStakeModifier, nStakeModifierHeight, nStakeModifierTime, false))
            return error("CheckStakeKernelHash(): failed to get kernel stake modifier \n");        
    }
*/
    if (this->nStakeModifier == 0) {
        // look for the modifier
        GetIndexFrom();
        if (!pindexFrom)
            return error("%s: failed to get index from", __func__);
        // TODO: This method must be removed from here in the short terms.. it's a call to an static method in kernel.cpp when this class method is only called from kernel.cpp, no comments..
        if (pindexFrom->nHeight >= Params().DGWStartHeight()) {
            if (!GetKernelStakeModifier(pindexFrom->GetBlockHash(), this->nStakeModifier, this->nStakeModifierHeight, this->nStakeModifierTime, false))
                return error("CheckStakeKernelHash(): failed to get kernel stake modifier");
        } else {
            if (!GetKernelStakeModifierPreDGW(pindexFrom->GetBlockHash(), this->nStakeModifier, this->nStakeModifierHeight, this->nStakeModifierTime, false))
                return error("CheckStakeKernelHash(): failed to get kernel stake modifier");
        }
    }
    nStakeModifier = this->nStakeModifier;

    return true;
}

CDataStream CIonStake::GetUniqueness()
{
    //The unique identifier for a ION stake is the outpoint
    if (chainActive.Height() >= Params().DGWStartHeight()) {
        CDataStream ss(SER_NETWORK, 0);
        ss << nPosition << txFrom.GetHash();
        return ss;
    } else {
        CDataStream ss(SER_GETHASH, 0);
        return ss;
    }
}

//The block that the UTXO was added to the chain
CBlockIndex* CIonStake::GetIndexFrom()
{
    if (pindexFrom)
        return pindexFrom;
    uint256 hashBlock = 0;
    CTransaction tx;
    if (GetTransaction(txFrom.GetHash(), tx, hashBlock, true)) {
        // If the index is in the chain, then set it as the "index from"
        if (mapBlockIndex.count(hashBlock)) {
            CBlockIndex* pindex = mapBlockIndex.at(hashBlock);
            if (chainActive.Contains(pindex))
                pindexFrom = pindex;
        }
    } else {
        LogPrintf("%s : failed to find tx %s\n", __func__, txFrom.GetHash().GetHex());
    }

    return pindexFrom;
}
