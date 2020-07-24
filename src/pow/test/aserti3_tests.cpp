// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Copyright (c) 2020 The Bitcoin Cash Node developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <pow/pow.h>
#include <pow/aserti3.h>

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <math.h>
#include <random.h>
#include <util/system.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

static CBlockIndex GetBlockIndex(CBlockIndex *pindexPrev, int64_t nTimeInterval,
                                 uint32_t nBits) {
    CBlockIndex block;
    block.pprev = pindexPrev;
    block.nHeight = pindexPrev->nHeight + 1;
    block.nTime = pindexPrev->nTime + nTimeInterval;
    block.nBits = nBits;

    block.nChainWork = pindexPrev->nChainWork + GetBlockProof(block);
    return block;
}

BOOST_FIXTURE_TEST_SUITE(aserti3_tests, BasicTestingSetup);

double TargetFromBits(const uint32_t nBits) {
    return (nBits & 0xffffff) * pow(256, ((nBits & 0xff000000) >> 24)-3);
}

double GetASERTApproximationError(const CBlockIndex *pindexPrev,
                                  const uint32_t finalBits,
                                  const CBlockIndex *pindexReferenceBlock) {
    const int64_t nHeightDiff = pindexPrev->nHeight - pindexReferenceBlock->nHeight;
    const int64_t nTimeDiff   = pindexPrev->nTime   - pindexReferenceBlock->nTime;
    const uint32_t initialBits = pindexReferenceBlock->nBits;

    BOOST_CHECK(nHeightDiff >= 0);
    double dInitialPow = TargetFromBits(initialBits);
    double dFinalPow   = TargetFromBits(finalBits);

    double dExponent = double(nTimeDiff - nHeightDiff * 600) / double(2*24*3600);
    double dTarget = dInitialPow * pow(2, dExponent);

    // printf("dTimeDiff = %ld\tdHeightDiff = %ld\tdExponent = %f\tinitialBits = %0x\tfinalBits = %0x\n", nTimeDiff, nHeightDiff, dExponent, initialBits, finalBits);
    // printf("dInitialPow = %.0f\tdFinalPow = %.0f\tdTarget = %.0f\n",dInitialPow, dFinalPow, dTarget);
    // printf("error = %7.5f\n", (dFinalPow - dTarget) / dTarget);
    return (dFinalPow - dTarget) / dTarget;
}

BOOST_AUTO_TEST_CASE(asert_difficulty_test) {
    DummyConfig config(CBaseChainParams::MAIN);

    std::vector<CBlockIndex> blocks(3000 + 2*24*3600);

    const Consensus::Params &params = config.GetChainParams().GetConsensus();
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    arith_uint256 currentPow = powLimit >> 3;
    uint32_t initialBits = currentPow.GetCompact();
    double dMaxErr = 0.0001166792656486;

    // Genesis block, also ASERT reference block in this test case.
    blocks[0] = CBlockIndex();
    blocks[0].nHeight = 0;
    blocks[0].nTime = 1269211443;
    blocks[0].nBits = initialBits;

    blocks[0].nChainWork = GetBlockProof(blocks[0]);

    // Block counter.
    size_t i;

    // Pile up some blocks every 10 mins to establish some history.
    for (i = 1; i < 150; i++) {
        blocks[i] = GetBlockIndex(&blocks[i - 1], 600, initialBits);
        BOOST_CHECK_EQUAL(blocks[i].nBits, initialBits);
    }

    CBlockHeader blkHeaderDummy;
    uint32_t nBits =
        GetNextASERTWorkRequired(&blocks[i - 1], &blkHeaderDummy, params, &blocks[0]);

    BOOST_CHECK_EQUAL(nBits, initialBits);

    // Difficulty stays the same as long as we produce a block every 10 mins.
    for (size_t j = 0; j < 10; i++, j++) {
        blocks[i] = GetBlockIndex(&blocks[i - 1], 600, nBits);
        BOOST_CHECK_EQUAL(
            GetNextASERTWorkRequired(&blocks[i], &blkHeaderDummy, params, &blocks[0]),
            nBits);
    }

    // If we add a two blocks whose solvetimes together add up to 1200s,
    // then the next block's target should be the same as the one before these blocks
    // (at this point, equal to initialBits).
    blocks[i] = GetBlockIndex(&blocks[i - 1], 300, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[0]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i-1], nBits, &blocks[0])) < dMaxErr);
    blocks[i] = GetBlockIndex(&blocks[i - 1], 900, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[0]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i-1], nBits, &blocks[0])) < dMaxErr);
    BOOST_CHECK_EQUAL(nBits, initialBits);
    BOOST_CHECK(nBits != blocks[i-1].nBits);

    // Same in reverse - this time slower block first, followed by faster block.
    blocks[i] = GetBlockIndex(&blocks[i - 1], 900, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[0]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i-1], nBits, &blocks[0])) < dMaxErr);
    blocks[i] = GetBlockIndex(&blocks[i - 1], 300, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[0]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i-1], nBits, &blocks[0])) < dMaxErr);
    BOOST_CHECK_EQUAL(nBits, initialBits);
    BOOST_CHECK(nBits != blocks[i-1].nBits);

    // Jumping forward 2 days should double the target
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 + 2*24*3600, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[0]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i-1], nBits, &blocks[0])) < dMaxErr);
    currentPow = arith_uint256().SetCompact(nBits) / 2;
    BOOST_CHECK_EQUAL(currentPow.GetCompact(), initialBits);

    // Iterate over the entire -2*24*3600..+2*24*3600 range to check that our integer approximation:
    //   1. Should be monotonic
    //   2. Should change target at least once every 8 seconds (worst-case: 15-bit precision on nBits)
    //   3. Should never change target by more than XXXX per 1-second step
    //   4. Never exceeds dMaxError in absolute error vs a double float calculation
    //   5. Has almost exactly the dMax and dMin errors we expect for the formula
    double dMin = 0;
    double dMax = 0;
    double dErr;
    double dMaxStep = 0;
    uint32_t nBitsRingBuffer[8];
    double dStep = 0;
    blocks[i] = GetBlockIndex(&blocks[i - 1], -2*24*3600 - 30, nBits);
    for (size_t j = 0; j < 4*24*3600 + 660; j++) {
        blocks[i].nTime++;
        nBits = GetNextASERTWorkRequired(&blocks[i], &blkHeaderDummy, params, &blocks[0]);

        if (j > 8) {
            // 1: Monotonic
            BOOST_CHECK(arith_uint256().SetCompact(nBits) >= arith_uint256().SetCompact(nBitsRingBuffer[(j-1)%8]));
            // 2: Changes at least once every 8 seconds (worst case: nBits = 1d008000 to 1d008001)
            BOOST_CHECK(arith_uint256().SetCompact(nBits) > arith_uint256().SetCompact(nBitsRingBuffer[j%8]));
            // 3: Check 1-sec step size
            dStep = (TargetFromBits(nBits) - TargetFromBits(nBitsRingBuffer[(j-1)%8])) / TargetFromBits(nBits);
            if (dStep > dMaxStep) dMaxStep = dStep;
            BOOST_CHECK(dStep < 0.0000314812106363); // from nBits = 1d008000 to 1d008001
        }
        nBitsRingBuffer[j%8] = nBits;

    // 4 and 5: check error vs double precision float calculation
        dErr = GetASERTApproximationError(&blocks[i], nBits, &blocks[0]);
        if (dErr < dMin) dMin = dErr;
        if (dErr > dMax) dMax = dErr;
        BOOST_CHECK(fabs(dErr) < dMaxErr);
        // printf("solveTime: %ld\tStep size: %.8f%%\tdErr: %.8f%%\tnBits: %0x\n", int64_t(blocks[i].nTime) - blocks[i-1].nTime, dStep*100, dErr*100, nBits);
    }
    BOOST_CHECK(dMin < -0.0001013168981059);
    BOOST_CHECK(dMin > -0.0001013168981060);
    BOOST_CHECK(dMax >  0.0001166792656485);
    BOOST_CHECK(dMax <  0.0001166792656486);
    //printf("Min error: %16.14f%%\tMax error: %16.14f%%\tMax step: %16.14f%%\n", dMin*100, dMax*100, dMaxStep*100);

    // Difficulty increases as long as we produce fast blocks
    for (size_t j = 0; j < 100; i++, j++) {
        uint32_t nextBits;
        arith_uint256 currentTarget;
        currentTarget.SetCompact(nBits);

        blocks[i] = GetBlockIndex(&blocks[i - 1], 500, nBits);
        nextBits = GetNextASERTWorkRequired(&blocks[i], &blkHeaderDummy, params, &blocks[0], false);
        arith_uint256 nextTarget;
        nextTarget.SetCompact(nextBits);

        // Make sure that difficulty is decreased
        BOOST_CHECK(nextTarget <= currentTarget);

        nBits = nextBits;
    }

}

void PrintTargets(const arith_uint256 initialTarget,
                  const arith_uint256 prevTarget,
                  const arith_uint256 nextTarget,
                  const arith_uint256 powLimit) {
    printf("\n"
           "initial=  %s\n"
           "prev=     %s\n"
           "next=     %s\n"
           "powLimit= %s\n",
           initialTarget.ToString().c_str(),
           prevTarget.ToString().c_str(),
           nextTarget.ToString().c_str(),
           powLimit.ToString().c_str());
}

void PrintCalcArgs(const arith_uint256 refTarget,
                   const int64_t targetSpacing,
                   const int64_t timeDiff,
                   const int64_t heightDiff,
                   const arith_uint256 expectedTarget,
                   const uint32_t expectednBits) {
    printf("\n"
           "ref=         %s\n"
           "spacing=     %ld\n"
           "timeDiff=    %ld\n"
           "heightDiff=  %ld\n"
           "expTarget=   %s\n"
           "exp nBits=   0x%08x\n",
           refTarget.ToString().c_str(),
           targetSpacing,
           timeDiff,
           heightDiff,
           expectedTarget.ToString().c_str(),
           expectednBits);
}


// Tests of the CalculateASERT function.
BOOST_AUTO_TEST_CASE(calculate_asert_test) {
    DummyConfig config(CBaseChainParams::MAIN);
    const Consensus::Params &params = config.GetChainParams().GetConsensus();
    const int64_t nHalfLife = params.nDAAHalfLife;

    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    arith_uint256 initialTarget = powLimit >> 4;
    int64_t height = 0;

    // Steady
    arith_uint256 nextTarget = CalculateASERT(initialTarget, params.nPowTargetSpacing, 600 /* nTimeDiff */, ++height, powLimit, nHalfLife, true);
    BOOST_CHECK(nextTarget == initialTarget);

    // A block that arrives in half the expected time
    nextTarget = CalculateASERT(initialTarget, params.nPowTargetSpacing, 600 + 300, ++height, powLimit, nHalfLife, true);
    BOOST_CHECK(nextTarget < initialTarget);

    // A block that makes up for the shortfall of the previous one, restores the target to initial
    arith_uint256 prevTarget = nextTarget;
    nextTarget = CalculateASERT(initialTarget, params.nPowTargetSpacing, 600 + 300 + 900, ++height, powLimit, nHalfLife, true);
    BOOST_CHECK(nextTarget > prevTarget);
    BOOST_CHECK(nextTarget == initialTarget);

    // Two days ahead of schedule should halve the target
    prevTarget = nextTarget;
    nextTarget = CalculateASERT(prevTarget, params.nPowTargetSpacing, 288*1200, 288, powLimit, nHalfLife, true);
    BOOST_CHECK(nextTarget == prevTarget * 2);

    // Two days behind schedule should halve the target
    prevTarget = nextTarget;
    nextTarget = CalculateASERT(prevTarget, params.nPowTargetSpacing, 288*0, 288, powLimit, nHalfLife, true);
    BOOST_CHECK(nextTarget == prevTarget / 2);
    BOOST_CHECK(nextTarget == initialTarget);

    // Ramp up from initialTarget to PowLimit - should only take 4 doublings...
    uint32_t powLimit_nBits = powLimit.GetCompact();
    uint32_t next_nBits;
    for (size_t k = 0; k < 3; k++) {
        prevTarget = nextTarget;
        nextTarget = CalculateASERT(prevTarget, params.nPowTargetSpacing, 288*1200, 288, powLimit, nHalfLife, true);
        BOOST_CHECK(nextTarget == prevTarget * 2);
        BOOST_CHECK(nextTarget < powLimit);
        next_nBits = nextTarget.GetCompact();
        BOOST_CHECK(next_nBits != powLimit_nBits);
    }

    prevTarget = nextTarget;
    nextTarget = CalculateASERT(prevTarget, params.nPowTargetSpacing, 288*1200, 288, powLimit, nHalfLife, true);
    next_nBits = nextTarget.GetCompact();
    BOOST_CHECK(nextTarget == prevTarget * 2);
    BOOST_CHECK(next_nBits == powLimit_nBits);

    // Fast periods now cannot increase target beyond POW limit, even if we try to overflow nextTarget.
    // prevTarget is a uint256, so 256*2 = 512 days would overflow nextTarget unless CalculateASERT
    // correctly detects this error
    nextTarget = CalculateASERT(prevTarget, params.nPowTargetSpacing, 512*144*600, 0, powLimit, nHalfLife, true);
    next_nBits = nextTarget.GetCompact();
    BOOST_CHECK(next_nBits == powLimit_nBits);

    // We also need to watch for underflows on nextTarget. We need to withstand an extra ~444 days worth of blocks.
    // This should bring down a powLimit target to the a minimum target of 1.
    nextTarget = CalculateASERT(powLimit, params.nPowTargetSpacing, 0, 2*(256-34)*144+1, powLimit, nHalfLife, true);
    next_nBits = nextTarget.GetCompact();
    BOOST_CHECK(next_nBits == arith_uint256(1).GetCompact());

    // Define a structure holding parameters to pass to CalculateASERT.
    // We are going to check some expected results  against a vector of
    // possible arguments.
    struct calc_params {
        arith_uint256 refTarget;
        int64_t targetSpacing;
        int64_t timeDiff;
        int64_t heightDiff;
        arith_uint256 expectedTarget;
        uint32_t expectednBits;
    };

    // Define some named input argument values
    const arith_uint256 SINGLE_300_TARGET { "00000000ffb1fffffffffffffffffffffffffffffffffffffffffffffffffffe" };

    // Define our expected input and output values.
    const std::vector<calc_params> calculate_args = {

        /* refTarget, targetSpacing, timeDiff, heightDiff, expectedTarget, expectednBits */

        { powLimit, 600, 0, 2*144, powLimit >> 1, 0x1c7fffff },
        { powLimit, 600, 0, 4*144, powLimit >> 2, 0x1c3fffff },
        { powLimit >> 1, 600, 0, 2*144, powLimit >> 2, 0x1c3fffff },
        { powLimit >> 2, 600, 0, 2*144, powLimit >> 3, 0x1c1fffff },
        { powLimit >> 3, 600, 0, 2*144, powLimit >> 4, 0x1c0fffff },
        { powLimit, 600, 0, 2*(256-34)*144, 3, 0x01030000 },
        { powLimit, 600, 0, 2*(256-34)*144+1, 1, 0x01010000 },
        { powLimit, 600, 0, 2*(256-33)*144, 1, 0x01010000 },  // 1 bit less since we do not need to shift to 0
        { powLimit, 600, 0, 2*(256-32)*144, 1, 0x01010000 },  // more will not decrease below 1
        { 1, 600, 0, 2*(256-32)*144, 1, 0x01010000 },
        { powLimit, 600, 2*(512-32)*144, 0, powLimit, powLimit_nBits },
        { 1, 600, (512-64)*144*600, 0, powLimit, powLimit_nBits },
        { powLimit, 600, 300, 1, SINGLE_300_TARGET, 0x1d00ffb1 },  // clamps to powLimit
    };

    for (auto& v : calculate_args) {
        nextTarget = CalculateASERT(v.refTarget, v.targetSpacing, v.timeDiff, v.heightDiff, powLimit, nHalfLife, true);
        next_nBits = nextTarget.GetCompact();
        if (nextTarget != v.expectedTarget || next_nBits != v.expectednBits) {
            PrintCalcArgs(v.refTarget, v.targetSpacing, v.timeDiff, v.heightDiff, v.expectedTarget, v.expectednBits);
            printf("nextTarget=  %s\n"
                   "next nBits=  0x%08x\n",
                   nextTarget.ToString().c_str(),
                   next_nBits);
            BOOST_CHECK(nextTarget == v.expectedTarget);
            BOOST_CHECK(next_nBits == v.expectednBits);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
