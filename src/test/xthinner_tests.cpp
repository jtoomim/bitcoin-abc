// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockencodings.h"
#include "chainparams.h"
#include "config.h"
#include "consensus/merkle.h"
#include "random.h"
#include "streams.h"
#include "util.h"
#include "version.h"
#include "xthinner.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

std::vector<std::pair<uint256, CTransactionRef>> extra_txns;

struct RegtestingSetup : public TestingSetup {
    RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(xthinner_tests, RegtestingSetup)

static CBlock BuildBlockTestCase() {
    CBlock block;
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42 * SATOSHI;

    block.vtx.resize(3);
    block.vtx[0] = MakeTransactionRef(tx);
    block.nVersion = 42;
    block.hashPrevBlock = InsecureRand256();
    block.nBits = 0x207fffff;

    tx.vin[0].prevout = COutPoint(InsecureRand256(), 0);
    block.vtx[1] = MakeTransactionRef(tx);

    tx.vin.resize(10);
    for (size_t i = 0; i < tx.vin.size(); i++) {
        tx.vin[i].prevout = COutPoint(InsecureRand256(), 0);
    }
    block.vtx[2] = MakeTransactionRef(tx);

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);

    GlobalConfig config;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, config)) {
        ++block.nNonce;
    }

    return block;
}

// Number of shared use_counts we expect for a tx we havent touched
// == 2 (mempool + our copy from the GetSharedTx call)
#define SHARED_TX_OFFSET 2

BOOST_AUTO_TEST_CASE(SimpleRoundTripTest) {
    CTxMemPool pool;
    CTxMemPool pool2;
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());
    const int tx_count = 250000;
    // These next two options add mempool desyncrhony. The ability to handle desynchrony is not
    // yet complete for XthinnerBlock, but works for XthinnerSegment with the code in the first
    // half of this test.
    const int recipientMissingTx = tx_count / 1000;
    const int recipientExtraTx = tx_count / 100;
    block.vtx.reserve(2 + tx_count);

    // If these lines are commented out, these transactions will be detected as missing by
    // the sender and will be included as PrefilledTransactions. Otherwise, they will
    // be missing for the receiver, and the receiver will have to specifically request them.
    //pool.addUnchecked(block.vtx[1]->GetId(), entry.FromTx(*block.vtx[1]));
    //pool.addUnchecked(block.vtx[2]->GetId(), entry.FromTx(*block.vtx[2]));

    std::vector<CMutableTransaction> vTx;
    vTx.reserve(tx_count);

    std::cout << "Testing Xthinner on a block with ";
    uint64_t nTime00 = GetTimeMicros();
    for (int i=0; i<tx_count + recipientExtraTx; i++) {
        CMutableTransaction new_tx;
        new_tx = CMutableTransaction();
        new_tx.nVersion = 1;
        new_tx.vin.resize(1);
        new_tx.vout.resize(1);
        new_tx.vout[0].nValue = 400 * SATOSHI;
        //new_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        new_tx.vin[0].prevout = COutPoint(InsecureRand256(), 0);

        if (i < tx_count)
            pool.addUnchecked(new_tx.GetId(), entry.FromTx(new_tx));
        if (i >= recipientMissingTx)
            pool2.addUnchecked(new_tx.GetId(), entry.FromTx(new_tx));

        if (i<tx_count) {
            vTx.push_back(new_tx);
        }
    }
    for (auto tx : vTx) {
        CTransaction out_tx(tx);
        block.vtx.push_back(MakeTransactionRef(out_tx));
    }

    uint64_t nTime01 = GetTimeMicros();
    std::cout << block.vtx.size() << " transactions with sender mempool size " << pool.size() << " and recipient mempool size " << pool2.size() << "\n";
    std::cout << "Tx/Block creation took " << nTime01-nTime00 << " usec, " << 1000*(nTime01-nTime00)/tx_count << " ns/tx (mempool)\n";

    std::sort(std::begin(block.vtx)+1, std::end(block.vtx),
                  [](const std::shared_ptr<const CTransaction> &a,
                     const std::shared_ptr<const CTransaction> &b) -> bool {
                      return a->GetId() < b->GetId();
                  });
    uint64_t nTime02 = GetTimeMicros();
    std::cout << "Sorting took " << nTime02-nTime01 << " usec, " << 1000*(nTime02-nTime01)/tx_count << " ns/tx (mempool)\n";

    uint64_t nTime0 = GetTimeMicros();

    LOCK(pool.cs);
    LOCK(pool2.cs);
    XthinnerSegment seg;

    BOOST_CHECK_EQUAL(seg.FromTXIDs(block.vtx, pool, 0, block.vtx.size()), 0);
    uint64_t nTime1 = GetTimeMicros();
    std::cout << "Single-threaded encoding took " << nTime1-nTime0 << " usec, " << 1000*(nTime1-nTime0)/tx_count << " ns/tx (mempool)\n";

    uint64_t recvBytes = 0;
    uint64_t sendBytes = 0;

    XthinnerSegment seg2;
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << seg;
    const std::string myStr = stream.str();
    std::cout << "String length: " << myStr.size() << "\n";
    recvBytes += myStr.size();
    stream >> seg2;

    uint64_t nTime2 = GetTimeMicros();
    std::cout << "Serialization/deserialization took " << nTime2-nTime1 << " usec, " << 1000*(nTime2-nTime1)/tx_count << " ns/tx (mempool)\n";

    std::vector<CTransactionRef> decodedVTx;
    std::vector<PrefilledTransaction> extra;
    decodedVTx.resize(block.vtx.size()); // fixme: should calculate based on data in segments
    BOOST_CHECK(1);
    seg2.ToTXIDs(decodedVTx, pool2, 0);
    BOOST_CHECK(1);

    uint64_t nTime3 = GetTimeMicros();
    std::cout << "Single-threaded decoding took " << nTime3-nTime2 << " usec, " << 1000*(nTime3-nTime2)/tx_count << " ns/tx (mempool)\n";

    int TTL = 4;
    while (TTL-- && seg2.vMissing.size()) {
        std::cout << "seg2.vMissing.size() = " << seg2.vMissing.size() << " on seg2.Update() round " << 4-TTL << "\n";
        for (int i=0; i<seg2.vMissing.size(); i++) {
            PrefilledTransaction pf;
            pf.index = seg2.vMissing[i];
            pf.tx = block.vtx[seg2.vMissing[i]];
            extra.push_back(pf);
        }
        CDataStream streamMissing(SER_NETWORK, PROTOCOL_VERSION);
        CDataStream streamExtra(SER_NETWORK, PROTOCOL_VERSION);
        streamMissing << seg2.vMissing;
        streamExtra << extra;
        std::cout << "Requesting " << seg2.vMissing.size() << " tx took " << streamMissing.str().size() << "/" << streamExtra.str().size() << " bytes tx/rx\n";
        sendBytes += streamMissing.str().size();
        recvBytes += streamExtra.str().size();

        for (auto it : extra) {
            seg2.mapExtra[it.index] = it.tx;
        }
        BOOST_CHECK(!seg2.Update(decodedVTx, extra, 0));
    }

    //BOOST_CHECK(!seg2.ToTXIDs(decodedVTx, pool2, 0));
    uint64_t nTime3a = GetTimeMicros();
    std::cout << "Filling missing slots and handling checksum errors took " << (3-TTL) << " rounds and " << nTime3a-nTime3 << " usec, " << 1000*(nTime3a-nTime3)/tx_count << " ns/tx (mempool)\n";

    for (int i=0; i<decodedVTx.size(); i++) {
        if (decodedVTx[i] == NULL) {
            std::cout << "Null pointer found at " << i << "\n";
            BOOST_CHECK(decodedVTx[i] != NULL);
        } else
        if (decodedVTx[i]->GetId() != block.vtx[i]->GetId()) {
            std::cout << "Position " << i << " doesn't match: "
                      << decodedVTx[i]->GetId().GetHex() << " vs "
                      << block.vtx[i]->GetId().GetHex() << "\n";
            BOOST_CHECK(decodedVTx[i]->GetId() == block.vtx[i]->GetId());
        }
    }

    std::cout << "Segment decoding was successful! Total bytes " << sendBytes << "/" << recvBytes << " tx/rx\n";

    // Check XthinnerBlock object creation, de/serialization
    XthinnerBlock xtblksrc(block, pool);
    XthinnerBlock xtblkdest;
    CDataStream stream2(SER_NETWORK, PROTOCOL_VERSION);
    stream2 << xtblksrc;
    stream2 >> xtblkdest;
    CBlock decBlock;
    xtblkdest.FillBlock(decBlock, pool2);

    for (int i=0; i<decodedVTx.size(); i++) {
        if (decodedVTx[i]->GetId() != block.vtx[i]->GetId()) {
            std::cout << "Position " << i << " doesn't match: " 
                      << decodedVTx[i]->GetId().GetHex() << " vs " 
                      << block.vtx[i]->GetId().GetHex() << "\n";
            BOOST_CHECK(decodedVTx[i]->GetId() == block.vtx[i]->GetId());
        }
    }

    CDataStream streamOrigBlk(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream streamDestBlk(SER_NETWORK, PROTOCOL_VERSION);
    streamOrigBlk << block;
    std::cout << "block serialized\n";
    streamDestBlk << decBlock;
    std::cout << "decBlock deserialized\n";
    std::string strOrigBlk = streamOrigBlk.str();
    std::string strDestBlk = streamDestBlk.str();

    std::cout << "Src block size: " << strOrigBlk.size() << " dest block size: " << strDestBlk.size() << " \n";
    if (!(strOrigBlk == strDestBlk)) {
        std::cout << "Orig block:\n";
        char psz[9];
        for (int i=0; i<strOrigBlk.size(); i++) {
            sprintf(psz, "%02x", (strOrigBlk[i]));
            std::cout << psz;
        }
        std::cout << "\n\nDest block:\n";
        for (int i=0; i<strDestBlk.size(); i++) {
            sprintf(psz, "%02x", (strDestBlk[i]));
            std::cout << psz;
        }
    }
    BOOST_CHECK(strOrigBlk == strDestBlk);
    std::cout << "Blocks match!\n";
/*    
    std::vector<XthinnerSegment> segments;
    #pragma omp parallel for
    for (int i = 0; i < block.vtx.size()/10240+1; ++i) {
        uint32_t start = i*10240 + (i==0 ? 1 : 0);
        uint32_t length = ((i+1)*10240-1 > block.vtx.size()-1) ? (block.vtx.size()-1) % 10240 : 10240;
        length = i==0 ? length-1 : length;
        segments[i].FromTXIDs(block.vtx, pool, start, length);
    }
    uint64_t nTime4 = GetTimeMicros();
    std::cout << "Multi-threaded  encoding took " << nTime4-nTime3 << " usec\n";
*/    
}

BOOST_AUTO_TEST_SUITE_END()
