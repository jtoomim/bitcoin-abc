// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Copyright (c) 2020 The Bitcoin Cash Node developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_ASERTI3_H
#define BITCOIN_POW_ASERTI3_H


#include <arith_uint256.h>

const CBlockIndex *GetASERTReferenceBlock(const CBlockIndex *pindexPrev,
                                          const Consensus::Params &params);

arith_uint256 CalculateASERT(const arith_uint256 refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 powLimit,
                             const int64_t nHalfLife,
                             bool debugASERT) noexcept;

uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                  const CBlockHeader *pblock,
                                  const Consensus::Params &params,
                                  const CBlockIndex *pindexReferenceBlock,
                                  bool debugASERT=false) noexcept __attribute__((optimize(0)));

#endif // BITCOIN_POW_ASERTI3_H
