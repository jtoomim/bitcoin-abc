// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Copyright (c) 2020 The Bitcoin Cash Node developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <pow/aserti3.h>
#include <consensus/activation.h>
//#include <consensus/params.h>
//#include <pow.h>
//#include <primitives/block.h>
//#include <primitives/blockhash.h>
#include <uint256.h>
//#include <util/system.h>

/**
 * Return pointer to the reference block used for ASERT.
 * As reference we use the Axion pre-fork block.
 * Note: other reference blocks are conceivable, e.g. a block some time in the
 * past before the Axion upgrade. For now the specification is not fixed on
 * using the exact pre-fork block.
 * This function is meant to be removed some time after the upgrade, once
 * the reference block is deeply buried.
 */
const CBlockIndex *GetASERTReferenceBlock(const CBlockIndex *pindexPrev,
                                          const Consensus::Params &params) {
    assert(pindexPrev != nullptr);

    // Walk back until we find the first block where ASERT isn't enabled,
    // which is also the first block for which Axion rules aren't enabled.
    const CBlockIndex *pindex = pindexPrev;
    while (pindex->pprev &&
           IsAxionEnabled(params, pindex)) {
        pindex = pindex->pprev;
    }
    return pindex;
}


/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                  const CBlockHeader *pblock,
                                  const Consensus::Params &params,
                                  const CBlockIndex *pindexReferenceBlock,
                                  bool debugASERT) noexcept {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    // Reference block is the block on which all ASERT scheduling calculations are based.
    // It too must exist.
    assert(pindexReferenceBlock != nullptr);

    // We make no further assumptions other than the height of the prev block must be >= that of the reference block.
    assert(pindexPrev->nHeight >= pindexReferenceBlock->nHeight);

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    const int64_t nTimeDiff = int64_t(pindexPrev->nTime) - int64_t(pindexReferenceBlock->GetBlockHeader().nTime);
    const int64_t nHeightDiff = pindexPrev->nHeight - pindexReferenceBlock->nHeight;

    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(pindexReferenceBlock->nBits);

    static const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // Do the actual target adaptation calculation in separate
    // CalculateCASERT() function
    arith_uint256 nextTarget = CalculateASERT(refBlockTarget,
                                              params.nPowTargetSpacing,
                                              nTimeDiff,
                                              nHeightDiff,
                                              powLimit,
                                              params.nDAAHalfLife,
                                              debugASERT);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 powLimit,
                             const int64_t nHalfLife,
                             bool debugASERT) noexcept {

    // Input target must never be zero nor exceed powLimit.
    assert (refTarget > 0 && refTarget <= powLimit);

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // This algorithm uses fixed-point math. The lowest rbits bits are after
    // the radix, and represent the "decimal" (or binary) portion of the value
    constexpr uint8_t rbits = 16;
    static_assert(rbits > 0);

    arith_uint256 nextTarget = refTarget;
    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from reference block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME*(height_diff+1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert( llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ull<<(63-rbits)) );
    int64_t exponent = ((nTimeDiff - nPowTargetSpacing * nHeightDiff) << rbits) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    const int64_t shifts = exponent >> rbits;

    if (shifts < 0) {
        nextTarget = nextTarget >> -shifts;
    } else {
        nextTarget = nextTarget << shifts;
    }
    // Remove everything but the decimal part from the exponent since we've
    // accounted for that through shifting.
    exponent -= (shifts << rbits);
    // What is left then should now be in the fixed point range [0, 1).
    assert(exponent >= 0 && exponent < 65536);

    if (nextTarget == 0 || nextTarget > powLimit) {
        if (shifts < 0) {
            return arith_uint256(1);
        } else {
            return powLimit;
        }
    }

    // Now we compute an approximated target * 2^(exponent)

    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    uint64_t factor = (195766423245049*exponent +
                       971821376*exponent*exponent +
                       5127*exponent*exponent*exponent + (1ull<<47))>>(rbits*3);
    nextTarget += (nextTarget * factor) >> rbits;

    // The last operation was strictly increasing, so it could have exceeded powLimit. Check and clamp again.
    if (nextTarget > powLimit) {
        return powLimit;
    }

    return nextTarget;
}
