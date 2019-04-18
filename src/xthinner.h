#ifndef XTHINNER_H
#define XTHINNER_H

#include "primitives/block.h"
#include "primitives/txid.h"
#include "txmempool.h"
#include "blockencodings.h"

#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <iostream>


// Protocol version supported by this code
// Bit 0x80 is debug flag
const uint8_t XTR_VERSION = 1 | 0x80;

// Note to implementers on projects (e.g. BU) that lack Compact Blocks (BIP152):
// Xthinner uses the following classes from the Compact Blocks implementation,
// which need to be copied over:
// PrefilledTransaction
// maybe BlockTransactionRequest
// maybe BlockTransactions

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
    XthinnerSegment() {};
    XthinnerSegment(const XthinnerSegment& src) :
            pushBytes(src.pushBytes),
            packedCommands(src.packedCommands),
            commandSize(src.commandSize),
            segmentLength(src.segmentLength),
            prefilled(src.prefilled),
            checksumSpec(src.checksumSpec),
            checksumData(src.checksumData),
            sm_missing(),
            vMissing(src.vMissing) {};

	int FromTXIDs(const std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start, uint32_t length, std::vector<std::pair<uint8_t, uint8_t> > checkSpec);
    // convenience wrapper that creates checkSpec
	int FromTXIDs(const std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start, uint32_t length);
    int ToTXIDs(std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start);
    int Update(std::vector<CTransactionRef> &vtx, const std::vector<PrefilledTransaction> &extra, uint32_t start);
    uint32_t size() {return segmentLength;}
    uint32_t prefilledsize() {return prefilled.size();}

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
    uint32_t txcount;
    std::vector<std::vector<PrefilledTransaction> > extra_txns;
    std::vector<XthinnerSegment> segments;
public:
    CBlockHeader header;

    // Dummy for serializaiton
    XthinnerBlock() {}
    XthinnerBlock(const CBlock &block, const CTxMemPool &pool);
    int FillBlock(CBlock &block, const CTxMemPool &pool);
    void GetMissing(std::vector<std::vector<uint32_t> > &vvMissing);
    uint32_t CountMissing();
    uint32_t size() {return txcount;}
    int Update(CBlock &block, const std::vector<std::vector<PrefilledTransaction> > &extra);
    int Update(CBlock &block, const std::vector<PrefilledTransaction> &extra);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(header);
        READWRITE(VARINT(txcount));
        READWRITE(segments);
    }
};


// XTROPTIONS message parsing/sending
struct XthinnerConfig {
    uint32_t nMessageSize = 13;
    uint8_t nXtrVersion = 0;
    bool fCanSendXtr = false;
    bool fCanRecvXtr = false;
    bool fAnnounceUnverified = true; // also affects pushes; non-binding, not yet implemented
    bool fPushXtrBlocks = false; // should the recipient of this message push to sender?
    uint64_t nPushMaxTxCount = 100*1000; // fixme: better default
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        uint32_t p = 0;
        READWRITE(VARINT(nMessageSize));
        if (nMessageSize>p)   {READWRITE(nXtrVersion);}          p++;
        if (nMessageSize>p)   {READWRITE(fCanSendXtr);}          p++;
        if (nMessageSize>p)   {READWRITE(fCanRecvXtr);}          p++;
        if (nMessageSize>p)   {READWRITE(fAnnounceUnverified);}  p++;
        if (nMessageSize>p)   {READWRITE(fPushXtrBlocks);}       p++;
        if (nMessageSize>p+7) {READWRITE(nPushMaxTxCount);}      p+=8;
        // discard or 0-pad any extra bytes for extensibility
        uint8_t padding = 0;
        for (; p < nMessageSize; p++) {
            READWRITE(padding);
        }
    }
};

// The XTRTXN message -- similar to Compact Blocks's BlockTransactions class
class XthinnerTransactions {
public:
    uint256 blockhash;
    //Xthinner and blocktorrent are inteded to be usable via UDP, which means
    // messages might arrive out of order or be duplicated. Including an index
    // of each tx in the response helps make the protocol more robust, and only
    // costs about 1% more bandwidth.
    std::vector<PrefilledTransaction> txn;

    XthinnerTransactions() {}
    XthinnerTransactions(const BlockTransactionsRequest &req)
        : blockhash(req.blockhash), txn(req.indices.size()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(blockhash);
        READWRITE(txn);
    }
};

int FetchTxFromBlock(const CBlock &block, const std::vector<uint32_t> &vMissing, std::vector<PrefilledTransaction> &extra);
int FetchTxFromBlock(const CBlock &block, const std::vector<std::vector<uint32_t> > &vvMissing, std::vector<std::vector<PrefilledTransaction> > &vExtra);

#endif
