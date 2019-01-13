#ifndef XTHINNER_H
#define XTHINNER_H

#include "primitives/block.h"
#include "primitives/txid.h"
#include "txmempool.h"
#include "blockencodings.h"

#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <iostream>


// Note to implementers on projects (e.g. BU) that lack Compact Blocks (BIP152):
// Xthinner uses the following classes from the Compact Blocks implementation,
// which need to be copied over:
// BlockTransactionRequest
// BlockTransactions
// maybe PrefilledTransaction

// need to implement xthinner-specific versions:
// CBlockHeaderAndShortTxIDs
// PartiallyDownloadedBlock

// This class is similar to CBlockHeaderAndShortTxIDs in Compact Blocks

class XthinnerSegment {
private:
    std::vector<uint8_t> pushBytes;
    std::vector<uint8_t> packedCommands;
    uint32_t commandSize;
    uint32_t segmentLength;
    std::vector<PrefilledTransaction> prefilled;

    // checksumSpec: The first uint8_t of the spec is the byte index in the TXID that is being checksummed
    // The second uint8_t is the power of 2 for the interval for the checksum
    // E.g. if the pair is (12, 3), that means that we sum the 12th byte (big endian order) for 
    // 1<<3 = 8 transactions at a time
    std::vector<std::pair<uint8_t, uint8_t> > checksumSpec; // first: byte pos; second: 
    std::vector<std::vector<uint8_t> > checksumData;
public:
    boost::shared_mutex sm_missing;
    std::vector<uint32_t> vMissing; // populated during 1st pass decoding (ToTXIDs)
    boost::shared_mutex sm_extra;
    std::map<uint32_t, CTransactionRef> mapExtra;
    XthinnerSegment() {};
    XthinnerSegment(const XthinnerSegment& src) : sm_missing(), sm_extra(),
            pushBytes(src.pushBytes),
            packedCommands(src.packedCommands),
            commandSize(src.commandSize),
            segmentLength(src.segmentLength),
            prefilled(src.prefilled),
            checksumSpec(src.checksumSpec),
            checksumData(src.checksumData),
            vMissing(src.vMissing),
            mapExtra(src.mapExtra) {};

	int FromTXIDs(const std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start, uint32_t length, std::vector<std::pair<uint8_t, uint8_t> > checkSpec);
	int FromTXIDs(const std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start, uint32_t length); // convenience wrapper that creates checkSpec
    int ToTXIDs(std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start);
    int Update(std::vector<CTransactionRef> &vtx, const std::vector<PrefilledTransaction> &extra, uint32_t start);
    int size() {return segmentLength;}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(VARINT(segmentLength));
        READWRITE(VARINT(commandSize));
        READWRITE(packedCommands);
        READWRITE(pushBytes);
        READWRITE(checksumSpec);
        READWRITE(checksumData);
        READWRITE(prefilled);
    }
};

class XthinnerBlock {
private:
protected:
    std::vector<XthinnerSegment> segments;
    uint32_t txcount;
    std::vector<std::vector<PrefilledTransaction> > extra_txns;
public:
    CBlockHeader header;

    // Dummy for serializaiton
    XthinnerBlock() {}
    XthinnerBlock(const CBlock &block, const CTxMemPool &pool);
    int FillBlock(CBlock &block, const CTxMemPool &pool);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(header);
        READWRITE(VARINT(txcount));
        READWRITE(segments);
    }
};
#endif
