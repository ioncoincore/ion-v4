// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The Ion Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

#include <math.h>

// ion: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextWorkRequiredOrig(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    uint256 bnTargetLimit = fProofOfStake ? Params().ProofOfStakeLimit() : Params().ProofOfWorkLimit();

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    if (nActualSpacing < 0) {
        nActualSpacing = Params().TargetSpacing();
    }
    else if (fProofOfStake && nActualSpacing > Params().TargetSpacing() * 10) {
         nActualSpacing = Params().TargetSpacing() * 10;
    }

    // target change every block
    // retarget with exponential moving toward target spacing
    // Includes fix for wrong retargeting difficulty by Mammix2
    uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    int64_t nInterval = fProofOfStake ? 10 : 10;
    bnNew *= ((nInterval - 1) * Params().TargetSpacing() + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * Params().TargetSpacing());

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

// This is MIDAS (Multi Interval Difficulty Adjustment System), a novel getnextwork algorithm.  It responds quickly to
// huge changes in hashing power, is immune to time warp attacks, and regulates the block rate to keep the block height
// close to the block height expected given the nominal block interval and the elapsed time.  How close the
// correspondence between block height and wall clock time is, depends on how stable the hashing power has been.  Maybe
// Bitcoin can wait 2 weeks between updates but no altcoin can.

// It is important that none of these intervals (5, 7, 9, 17) have any common divisor; eliminating the existence of
// harmonics is an important part of eliminating the effectiveness of timewarp attacks.
void avgRecentTimestamps(const CBlockIndex* pindexLast, int64_t *avgOf5, int64_t *avgOf7, int64_t *avgOf9, int64_t *avgOf17)
{
  int blockoffset = 0;
  int64_t oldblocktime;
  int64_t blocktime;

  *avgOf5 = *avgOf7 = *avgOf9 = *avgOf17 = 0;
  if (pindexLast)
    blocktime = pindexLast->GetBlockTime();
  else blocktime = 0;

  for (blockoffset = 0; blockoffset < 17; blockoffset++)
  {
    oldblocktime = blocktime;
    if (pindexLast)
    {
      pindexLast = pindexLast->pprev;
      blocktime = pindexLast->GetBlockTime();
    }
    else
    { // genesis block or previous
    blocktime -= Params().TargetSpacing();
    }
    // for each block, add interval.
    if (blockoffset < 5) *avgOf5 += (oldblocktime - blocktime);
    if (blockoffset < 7) *avgOf7 += (oldblocktime - blocktime);
    if (blockoffset < 9) *avgOf9 += (oldblocktime - blocktime);
    *avgOf17 += (oldblocktime - blocktime);    
  }
  // now we have the sums of the block intervals. Division gets us the averages. 
  *avgOf5 /= 5;
  *avgOf7 /= 7;
  *avgOf9 /= 9;
  *avgOf17 /= 17;
}

unsigned int GetNextWorkRequiredMidas(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    int64_t avgOf5;
    int64_t avgOf9;
    int64_t avgOf7;
    int64_t avgOf17;
    int64_t toofast;
    int64_t tooslow;
    int64_t difficultyfactor = 10000;
    int64_t now;
    int64_t BlockHeightTime;

    int64_t nFastInterval = (Params().TargetSpacing() * 9 ) / 10; // seconds per block desired when far behind schedule
    int64_t nSlowInterval = (Params().TargetSpacing() * 11) / 10; // seconds per block desired when far ahead of schedule
    int64_t nIntervalDesired;

    uint256 bnTargetLimit = fProofOfStake ? Params().ProofOfStakeLimit() : Params().ProofOfWorkLimit();
    unsigned int nTargetLimit = bnTargetLimit.GetCompact();
    
    if (pindexLast == NULL)
        // Genesis Block
        return nTargetLimit;
   
    // Regulate block times so as to remain synchronized in the long run with the actual time.  The first step is to
    // calculate what interval we want to use as our regulatory goal.  It depends on how far ahead of (or behind)
    // schedule we are.  If we're more than an adjustment period ahead or behind, we use the maximum (nSlowInterval) or minimum
    // (nFastInterval) values; otherwise we calculate a weighted average somewhere in between them.  The closer we are
    // to being exactly on schedule the closer our selected interval will be to our nominal interval (TargetSpacing).

    now = pindexLast->GetBlockTime();
    BlockHeightTime = Params().GenesisBlock().nTime + pindexLast->nHeight * Params().TargetSpacing();
    
    if (now < BlockHeightTime + Params().TargetTimespanMidas() && now > BlockHeightTime )
    // ahead of schedule by less than one interval.
    nIntervalDesired = ((Params().TargetTimespanMidas() - (now - BlockHeightTime)) * Params().TargetSpacing() +  
                (now - BlockHeightTime) * nFastInterval) / Params().TargetSpacing();
    else if (now + Params().TargetTimespanMidas() > BlockHeightTime && now < BlockHeightTime)
    // behind schedule by less than one interval.
    nIntervalDesired = ((Params().TargetTimespanMidas() - (BlockHeightTime - now)) * Params().TargetSpacing() + 
                (BlockHeightTime - now) * nSlowInterval) / Params().TargetTimespanMidas();

    // ahead by more than one interval;
    else if (now < BlockHeightTime) nIntervalDesired = nSlowInterval;
    
    // behind by more than an interval. 
    else  nIntervalDesired = nFastInterval;
    
    // find out what average intervals over last 5, 7, 9, and 17 blocks have been. 
    avgRecentTimestamps(pindexLast, &avgOf5, &avgOf7, &avgOf9, &avgOf17);    

    // check for emergency adjustments. These are to bring the diff up or down FAST when a burst miner or multipool
    // jumps on or off.  Once they kick in they can adjust difficulty very rapidly, and they can kick in very rapidly
    // after massive hash power jumps on or off.
    
    // Important note: This is a self-damping adjustment because 8/5 and 5/8 are closer to 1 than 3/2 and 2/3.  Do not
    // screw with the constants in a way that breaks this relationship.  Even though self-damping, it will usually
    // overshoot slightly. But normal adjustment will handle damping without getting back to emergency.
    toofast = (nIntervalDesired * 2) / 3;
    tooslow = (nIntervalDesired * 3) / 2;

    // both of these check the shortest interval to quickly stop when overshot.  Otherwise first is longer and second shorter.
    if (avgOf5 < toofast && avgOf9 < toofast && avgOf17 < toofast)
    {  //emergency adjustment, slow down (longer intervals because shorter blocks)
      LogPrint("difficulty", "GetNextWorkRequired EMERGENCY RETARGET\n");
      difficultyfactor *= 8;
      difficultyfactor /= 5;
    }
    else if (avgOf5 > tooslow && avgOf7 > tooslow && avgOf9 > tooslow)
    {  //emergency adjustment, speed up (shorter intervals because longer blocks)
      LogPrint("difficulty", "GetNextWorkRequired EMERGENCY RETARGET\n");
      difficultyfactor *= 5;
      difficultyfactor /= 8;
    }

    // If no emergency adjustment, check for normal adjustment. 
    else if (((avgOf5 > nIntervalDesired || avgOf7 > nIntervalDesired) && avgOf9 > nIntervalDesired && avgOf17 > nIntervalDesired) ||
         ((avgOf5 < nIntervalDesired || avgOf7 < nIntervalDesired) && avgOf9 < nIntervalDesired && avgOf17 < nIntervalDesired))
    { // At least 3 averages too high or at least 3 too low, including the two longest. This will be executed 3/16 of
      // the time on the basis of random variation, even if the settings are perfect. It regulates one-sixth of the way
      // to the calculated point.
      LogPrint("difficulty", "GetNextWorkRequired RETARGET\n");
      difficultyfactor *= (6 * nIntervalDesired);
      difficultyfactor /= (avgOf17 +(5 * nIntervalDesired));
    }

    // limit to doubling or halving.  There are no conditions where this will make a difference unless there is an
    // unsuspected bug in the above code.
    if (difficultyfactor > 20000) difficultyfactor = 20000;
    if (difficultyfactor < 5000) difficultyfactor = 5000;

    uint256 bnNew;
    uint256 bnOld;

    bnOld.SetCompact(pindexLast->nBits);

    if (difficultyfactor == 10000) // no adjustment. 
      return(bnOld.GetCompact());

    bnNew = bnOld / difficultyfactor;
    bnNew *= 10000;

    if (bnNew > Params().ProofOfWorkLimit())
      bnNew = Params().ProofOfWorkLimit();

    LogPrint("difficulty", "Actual time %d, Scheduled time for this block height = %d\n", now, BlockHeightTime );
    LogPrint("difficulty", "Nominal block interval = %d, regulating on interval %d to get back to schedule.\n", 
          Params().TargetSpacing(), nIntervalDesired );
    LogPrint("difficulty", "Intervals of last 5/7/9/17 blocks = %d / %d / %d / %d.\n",
          avgOf5, avgOf7, avgOf9, avgOf17);
    LogPrint("difficulty", "Difficulty Before Adjustment: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
    LogPrint("difficulty", "Difficulty After Adjustment:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
     
}

unsigned int GetNextWorkRequiredDGW(const CBlockIndex* pindexLast, const CBlockHeader* pblock)
{
    /* current difficulty formula, ion - DarkGravity v3, written by Evan Duffield - evan@dashpay.io */
    const CBlockIndex* BlockLastSolved = pindexLast;
    const CBlockIndex* BlockReading = pindexLast;
    int64_t nActualTimespan = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 24;
    int64_t PastBlocksMax = 24;
    int64_t CountBlocks = 0;
    uint256 PastDifficultyAverage;
    uint256 PastDifficultyAveragePrev;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < Params().DGWStartHeight() + PastBlocksMin) {
        return Params().ProofOfWorkLimit().GetCompact();
    }

    if (pindexLast->nHeight > Params().LAST_POW_BLOCK()) {
        uint256 bnTargetLimit = (~uint256(0) >> 24);
        int64_t nTargetSpacing = 60;
        int64_t nTargetTimespan = 40 * Params().TargetTimespanDGW();

        int64_t nActualSpacing = 0;
        if (pindexLast->nHeight != 0)
            nActualSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();

        if (nActualSpacing < 0)
            nActualSpacing = 1;

        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        uint256 bnNew;
        bnNew.SetCompact(pindexLast->nBits);

        int64_t nInterval = nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if (bnNew <= 0 || bnNew > bnTargetLimit)
            bnNew = bnTargetLimit;

        return bnNew.GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) {
            break;
        }
        CountBlocks++;

        if (CountBlocks <= PastBlocksMin) {
            if (CountBlocks == 1) {
                PastDifficultyAverage.SetCompact(BlockReading->nBits);
            } else {
                PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks) + (uint256().SetCompact(BlockReading->nBits))) / (CountBlocks + 1);
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if (LastBlockTime > 0) {
            int64_t Diff = (LastBlockTime - BlockReading->GetBlockTime());
            nActualTimespan += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    uint256 bnNew(PastDifficultyAverage);

    int64_t _nTargetTimespan = CountBlocks * Params().TargetSpacing();

    if (nActualTimespan < _nTargetTimespan / 3)
        nActualTimespan = _nTargetTimespan / 3;
    if (nActualTimespan > _nTargetTimespan * 3)
        nActualTimespan = _nTargetTimespan * 3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= _nTargetTimespan;

    if (bnNew > Params().ProofOfWorkLimit()) {
        bnNew = Params().ProofOfWorkLimit();
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, bool fProofOfStake)
{
    if (pindexLast->nHeight < Params().MidasStartHeight()){
        return GetNextWorkRequiredOrig(pindexLast, fProofOfStake);
    } else if (pindexLast->nHeight >= Params().MidasStartHeight() && pindexLast->nHeight < Params().Zerocoin_StartHeight() -1){
        return GetNextWorkRequiredMidas(pindexLast, fProofOfStake);
    } else if (pindexLast->nHeight >= Params().Zerocoin_StartHeight() -1 && pindexLast->nHeight < Params().Zerocoin_StartHeight()) {
        return GetNextWorkRequiredDGW(pindexLast, pblock);
    } else if (pindexLast->nHeight >= Params().Zerocoin_StartHeight()) {
        return GetNextWorkRequiredDGW(pindexLast, pblock);
    } else {
        return GetNextWorkRequiredDGW(pindexLast, pblock);
    }  
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (Params().SkipProofOfWorkCheck())
        return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget && Params().NetworkID() != CBaseChainParams::REGTEST)
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}
