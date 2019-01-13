#include "primitives/block.h"
#include "primitives/txid.h"
#include "random.h"
#include "txmempool.h"
#include "util.h"
#include "xthinner.h"

#include <iostream>



int XthinnerSegment::FromTXIDs(const std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start, uint32_t length) {
    std::vector<std::pair<uint8_t, uint8_t> > spec;
    FastRandomContext insecure_rand;
    spec.reserve(4);
    for (int i=0; i<4; i++) {
        // every 16, 64, 256, 1024 tx
        spec.push_back(std::make_pair(insecure_rand.rand32() % 24, 4 + 2*i));
    }
    return this->FromTXIDs(vtx, pool, start, length, spec);
}
int XthinnerSegment::FromTXIDs(const std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start,
                               uint32_t length, std::vector<std::pair<uint8_t, uint8_t> > checkSpec) {
    // https://medium.com/@j_73307/benefits-of-ltor-in-block-entropy-encoding-or-8d5b77cc2ab0

    // The encoding scheme is basically encoding the transactions as a prefix tree
    // except that we omit all bytes that are not necessary to disambiguate a tx 
    // from the recipient's mempool.
    // The algorithm for encoding our tree uses a stack which we interact with in four 
    // possible operations per transaction:
    // 1. We can pop 1 or more bytes off the stack.
    // 2. We can push 1 or more bytes onto the stack
    // 3. We can commit to a transaction that uses the prefix encoded in the stack.
    // 4. We can accumulate into zero or more checksum bytes
    // For the pop stage, we encode a 1 for every pop we do after the first, and a 0 when done
    // for the push stage, we encode a 1 for every push we do after the first, and a 0 when done
    // For the commit stage, we encode nothing, as it's implicit as the 0 from the push stage.

    // Finally, we encode 1-byte error detection checksums at a few different levels
    // E.g. sum a byte from every 8 tx into a 1st-order checksum
    // and sum a byte from every 32 tx into a 2nd-order checksum
    // and sum a byte from every 128 tx into a 3rd-order checksum
    const int debug = 3;
    AssertLockHeld(pool.cs);
    uint64_t nTime0 = GetTimeMicros();

    if (start+length > vtx.size()) return 1;

    segmentLength = length;
    std::vector<uint8_t> stack; // big endian order, unlike txids

    std::vector<bool> commands;

    char psz[9]; // for hex-formatting debugging output

    auto it = pool.mapTx.get<txid_score>().begin();
    auto lasthit = pool.mapTx.get<txid_score>().begin();
    auto preit = pool.mapTx.get<txid_score>().begin();
    auto postit = pool.mapTx.get<txid_score>().begin();

    std::vector<uint8_t> checkInFlight(checkSpec.size(), 0);
    checksumData.resize(checkSpec.size());
    checksumSpec.resize(checkSpec.size());
    for (int i=0; i<checkSpec.size(); i++) {
        checksumSpec[i] = checkSpec[i];
        checksumData[i].reserve((length)/(1<<checksumSpec[i].second) + 1);
    }

    if (debug>4) {
        std::cout << "Block transactions:\n";
        for (auto tx : vtx) {
            std::cout << tx->GetId().GetHex() << "\n";
        }
        std::cout << "\nMempool transactions:\n";
        while (it != pool.mapTx.get<txid_score>().end()) {
            std::cout << it->GetTx().GetId().GetHex() << "\n";
            it++;
        }
        std::cout << "\n";
    }

    it = pool.mapTx.get<txid_score>().begin();
    //it = pool.mapTx.get<txid_score>().find(*pool.mapTx.find(vtx[start]));
    for (uint32_t bPos = start; bPos < start+length; bPos++) {
        TxId txid = vtx[bPos]->GetId();
        if (debug>5) std::cout << txid.GetHex() << " is next tx, stack is ";
        for (auto byte : stack) {
            sprintf(psz, "%02x", byte);
            if (debug>5) std::cout << psz;
        }
        if (debug>5) std::cout << "\n";

        // 1. We pop bytes off the stack that don't match our current tx
        // First pop is a freebie (unless we're just getting started)
        if (stack.size()) {
            stack.pop_back();
            if (debug>6) std::cout << "POP ";

        }
        // Note: TxIds are little-endian, but our stack is big-endian
        bool matched = false;
        while (stack.size() && !matched) {
            matched = true;
            for (int i=stack.size()-1; i > -1 && matched; i--) {
                if (stack[i] != *(txid.end() - i - 1)) {
                    matched = false;
                    commands.push_back(1);
                    stack.pop_back();
                    if (debug>6) std::cout << "pop ";
                }
            }
        }

        commands.push_back(0);
        if (debug>6) std::cout << "\n";

        // 2. We push bytes onto the stack in order to disambiguate between neighboring
        // mempool transactions
        // 2(a) find the txid in mempool
        // fixme: use find() when appropriate in a non-slow fashion
        /*for (int n=0; n<40 
               && it != pool.mapTx.get<txid_score>().end()
               && it->GetTx().GetId() < txid; n++) {*/
        while (it != pool.mapTx.get<txid_score>().end()
               && it->GetTx().GetId() < txid
               && bPos != 0) {
            it++;
        }

        // this code is slow, so it's disabled for now
        //if (it->GetTx().GetId() != txid) {
            // there has to be a better way of doing this
            // we need to search for the mempoolentry, not the txid
        //    it = pool.mapTx.get<txid_score>().find(*pool.mapTx.find(txid));
        //}

        if (it->GetTx().GetId() != txid) {
            // If we don't have the transaction in our mempool, we push it as
            // a prefilled transactioin. The mempool iterators won't match,
            // so we won't specify more than one pushbyte, but that won't matter,
            // as the recipient will get the prefilledtxn.
            PrefilledTransaction pf;
            pf.index = bPos;
            pf.tx = vtx[bPos];
            prefilled.push_back(PrefilledTransaction(pf));
        } else {
            lasthit = it;
        }

        // 2(b) First push is a freebie
        pushBytes.push_back(*(txid.end() - stack.size()-1));
        stack.push_back(*(txid.end() - stack.size()-1));
        sprintf(psz, "%02x", (stack.back()));
        if (debug>6) std::cout << " freepushed " << psz << " onto stack\n";

        sprintf(psz, "%02x", (*(txid.end() - stack.size())));
        if (debug>6) std::cout << "stack size is " << stack.size();
        if (debug>6) std::cout << " and last txid byte is " << psz << "\n";

        // 2(c).  Push enough bytes so that we can disambiguate between mempool neighbors
        preit = it; postit = it;
        preit--; postit++;

        if (debug>5) std::cout << preit->GetTx().GetId().GetHex() << " is pre tx\n";
        if (debug>5) std::cout << txid.GetHex() << " is crnt tx, stack is ";
        for (auto byte : stack) {
            sprintf(psz, "%02x", byte);
            if (debug>5) std::cout << psz;
        }
        if (debug>5) std::cout << "\n" << postit->GetTx().GetId().GetHex() << " is post tx\n";


        bool leftmatched = it != pool.mapTx.get<txid_score>().begin();;
        bool rightmatched = postit != pool.mapTx.get<txid_score>().end();
        for (int i=stack.size(); i<32 && (leftmatched || rightmatched); i++) {
            if (leftmatched && *(preit->GetTx().GetId().end()-i) != stack.back()) {
                
                sprintf(psz, "%02x", (*(preit->GetTx().GetId().end()-i)));
                if (debug>5) std::cout << " left unmatched on " << psz;
                leftmatched = false;

            }
            if (rightmatched && *(postit->GetTx().GetId().end()-i) != stack.back()) {
                sprintf(psz, "%02x", (*(postit->GetTx().GetId().end()-i)));
                if (debug>5) std::cout << " right unmatched on " << psz;
                rightmatched = false;
            }
            if (leftmatched || rightmatched) {
                pushBytes.push_back(*(txid.end() - stack.size()-1));
                stack.push_back(*(txid.end() - stack.size()-1));
                commands.push_back(1);
                sprintf(psz, "%02x", (stack.back()));
                if (debug>5) std::cout << " pushed " << psz << " onto stack\n";
            }
        }

        // 3. Commit to a transaction
        commands.push_back(0);
        if (debug>5) std::cout << "\n\n";

        // 4. Compute checksum bytes
        for (int i=0; i<checksumSpec.size(); i++) {
            checkInFlight[i] ^= *(txid.end() - checksumSpec[i].first -1);
            if ((bPos+1) % (1<<checksumSpec[i].second) == 0 ||
                bPos == start+length-1) {
                checksumData[i].push_back(checkInFlight[i]);
                checkInFlight[i] = 0;
            }
        }
    }
    int64_t nTime1 = GetTimeMicros();
    if (debug>3) std::cout << "Encoding took " << nTime1-nTime0 << " usec\n";

    packedCommands.clear();
    commandSize = commands.size();
    packedCommands.reserve(commandSize);
    uint8_t byte = 0;

    for (int i=0; i<commands.size(); i++) {
        byte |= (uint8_t)commands[i] << (i%8);
        if (i%8==7) {
            packedCommands.push_back(byte);
            byte = 0;
        }
    }
    if ((commands.size()-1)%8 != 7) {
        packedCommands.push_back(byte);
    }

    uint64_t checksumTotalSize = 0;
    for (int i=0; i<checksumSpec.size(); i++) {
        checksumTotalSize += checksumData[i].size() + 2; // 2 bytes for spec
    }
    uint64_t totalsize = pushBytes.size() + (commands.size()+7)/8 + checksumTotalSize;
    if (debug>2) {
        std::cout << "Encoding is " << pushBytes.size() << " pushBytes, " << commands.size() << " commands, " << checksumTotalSize << " checksum bytes\n";
        std::cout << "total  " << totalsize << " bytes, " << float(totalsize*8)/float(length) << " bits/tx\n";
        std::cout << "Prefills: " << prefilled.size() << "\n";
    }

    return 0;
}

int XthinnerSegment::ToTXIDs(std::vector<CTransactionRef> &vtx, const CTxMemPool &pool, uint32_t start) {
    const int debug = 3;

    uint32_t nMissing = 0;
    uint32_t nAmbiguous = 0;

    if (vtx.size() < start + segmentLength) {
        std::cout << "Output vector is not big enough for Xthinner unpacking\n";
        return 1;
    }
    uint32_t cmdPos = 0;
    uint32_t pushBytePos = 0;
    std::vector<uint8_t> stack; // big endian order, unlike txids
    TxId stackTxId;
    
    char psz[9]; // for hex-formatting debugging output
    if (debug>5) {
        std::cout << "pushBytes is:\n";
        for (int i=0; i<pushBytes.size(); i++) {
            sprintf(psz, "%02x", (pushBytes[i]));
            std::cout << psz;
        }
        std::cout << "\n";
    }
    
    auto it = pool.mapTx.get<txid_score>().begin();
    auto lasthit = pool.mapTx.get<txid_score>().begin();
    auto postit = pool.mapTx.get<txid_score>().begin();

    auto pf_iter = prefilled.begin();
    while (pf_iter != prefilled.end() && pf_iter->index < start) pf_iter++;
    auto ex_iter = mapExtra.upper_bound(start);

    std::vector<bool> expectError(checksumSpec.size(), false);
    std::vector<uint8_t> checkInFlight(checksumSpec.size(), 0);

    for (int i=1; i<checksumSpec.size(); i++) {
        if (checksumSpec[i].second < checksumSpec[i-1].second) {
            std::cout << "Out-of-order checksum intervals are not supported by this Xthinner decoder\n";
            return 5;
        }
    }

    for (uint32_t pos = start; pos < start + segmentLength; pos++) {
        // 1. We pop bytes off the stack that don't match our current tx
        // First pop is a freebie (unless we're just getting started)
        if (stack.size()) {
            stack.pop_back();
            if (debug>6) std::cout << "POP ";
        }
        // Then we pop once for every consecutive 1 in our command vector
        while (packedCommands[cmdPos/8] & (1<<(cmdPos++%8))) {
            if (!stack.size()) {
                std::cout << "Tried to pop something off an empty stack\n";
                return 2;
            }
            stack.pop_back();
            if (debug>6) std::cout << "POP ";
        }

        // 2. We push bytes onto the stack in order to disambiguate between neighboring
        // mempool transactions
        // First push is a freebie
        if (pushBytePos >= pushBytes.size()) {
            std::cout << "Tried to push more bytes than we have\n";
            return 3;
        }
        if (stack.size() > 31) {
            std::cout << "Tried to overflow stack. Naughty.\n";
            return 4;
        }
        stack.push_back(pushBytes[pushBytePos++]);
        sprintf(psz, "%02x", (stack.back()));
        if (debug>6) std::cout << "PUSH " << psz << " ";


        while (packedCommands[cmdPos/8] & (1<<(cmdPos++%8))) {
            if (pushBytePos >= pushBytes.size()) {
                std::cout << "Tried to push more bytes than we have\n";
                return 3;
            }
            if (stack.size() > 31) {
                std::cout << "Tried to overflow stack. Naughty.\n";
                return 4;
            }
            stack.push_back(pushBytes[pushBytePos++]);
            sprintf(psz, "%02x", (stack.back()));
            if (debug>6) std::cout << "PUSH " << psz << " ";
        }

        if (debug>6) std::cout << "\n";

        // 3. Finding the correct transaction from mempool or prefilledtxn
        bool match = true;
        bool nextmatch = false;

        if (ex_iter != mapExtra.end() && ex_iter->first < pos) ex_iter++;
        if (pf_iter != prefilled.end() && pf_iter->index == pos) {
            if (debug>3) std::cout << "Found prefilled at pos=" << pos << " with hash " << pf_iter->tx->GetId().GetHex() << "\n";
            vtx[pos] = pf_iter->tx;
            pf_iter++;
        } else if (ex_iter != mapExtra.end() && ex_iter->first == pos) {
            if (debug>3) std::cout << "Found extra at pos=" << pos << " with hash " << ex_iter->second->GetId().GetHex() << "\n";
            vtx[pos] = ex_iter->second;
            ex_iter++;
        } else {
            for (int i=0; i<32; i++) {
                *(stackTxId.end() - i -1) = (i<stack.size()) ? stack[i] : 0;
            }
            // find the tx in mempool -- iteration is faster than using find()
            while (it != pool.mapTx.get<txid_score>().end() && it->GetTx().GetId() < stackTxId) {
                it++;
            }

            nextmatch = true;
            // If we didn't find it, back up to avoid OOB memory access
            if (it == pool.mapTx.get<txid_score>().end()) it--;
            postit = it;
            postit++;
            if (postit == pool.mapTx.get<txid_score>().end()) {
                postit--;
                nextmatch = false;
            }
            TxId candidateTxId = it->GetTx().GetId();
            TxId postTxId = postit->GetTx().GetId();
            for (int i=0; i<stack.size(); i++) {
                if (*(candidateTxId.end() - i - 1) != stack[i]) {
                    if (debug > 3) std::cout << "Transaction missing! Pos " << pos << " stack " << stackTxId.GetHex() << " < " << candidateTxId.GetHex() << "\n";
                    sm_missing.lock();
                    vMissing.push_back(pos);
                    sm_missing.unlock();
                    nMissing++;
                    match = false;
                    for (int i=0; i<checksumSpec.size(); i++) {expectError[i]=true;}
                    it = lasthit;
                    break;
                }
                if (nextmatch && *(postTxId.end() - i - 1) != stack[i]) {
                    nextmatch = false;
                }
            }
            if (match && !nextmatch) {
                vtx[pos] = it->GetSharedTx();
                lasthit = it;
            }
            else if (match && nextmatch) {
                // This scenario can be addressed by seeing which of the transactions
                // satisfies the checksum requirements, but that costs
                // more programmer time than it's worth right now to avoid rare retransmissions
                sm_missing.lock();
                vMissing.push_back(pos);
                sm_missing.unlock();
                if (debug > 3) std::cout << "Transaction ambiguous! Pos " << pos << " stack " << stackTxId.GetHex() << " matches "
                          << it->GetTx().GetId().GetHex() << " and " << postit->GetTx().GetId().GetHex() << "\n";
                nAmbiguous++;
                for (int i=0; i<checksumSpec.size(); i++) {expectError[i]=true;}
            }
        }

        // 4. Check checksum bytes
        for (int i=0; i<checksumSpec.size(); i++) {
            if (match && !nextmatch) {
                checkInFlight[i] ^= *(vtx[pos]->GetId().end() - checksumSpec[i].first -1);
            }
            if ((pos+1) % (1<<checksumSpec[i].second) == 0 || pos == start+segmentLength-1) {
                int j = pos / (1<<checksumSpec[i].second);
                if (checksumData[i][j] != checkInFlight[i] && !expectError[i]) {
                    if (debug>3) std::cout << "Checksum error at pos " << pos << " interval " << (1<<checksumSpec[i].second) << "\n";
                    for (int k=pos-(1<<checksumSpec[i].second)+1; k<pos+1; k++) {
                        sm_missing.lock();
                        vMissing.push_back(k);
                        sm_missing.unlock();
                    }
                    for (int k=i+1; k<checksumSpec.size(); k++) {expectError[k]=true;}
                }
                else if (checksumData[i][j] == checkInFlight[i]) {
                    //std::cout << "Checksum match at pos " << pos << " interval " << (1<<checksumSpec[i].second) << "\n";
                }
                checkInFlight[i] = 0;
                expectError[i] = false;
            } else {
                //std::cout << "pos=" << pos << " i=" << i << " (pos+1) % (1<<checksumSpec[i].second) = " << ((pos+1) % (1<<checksumSpec[i].second)) << " expectError[i]=" << expectError[i] << "\n";
            }
        }
    }
    if (debug > 2) std::cout << "Found " << nAmbiguous << " ambiguities and " << nMissing << " missing tx during first pass decode\n";
    return 0;
}
int XthinnerSegment::Update(std::vector<CTransactionRef> &vtx, const std::vector<PrefilledTransaction> &extra, uint32_t start) {
    const int debug = 2;
    sm_extra.lock();
    for (auto ex : extra) {
        mapExtra[ex.index] = ex.tx;
        vtx[ex.index] = ex.tx;
    }
    sm_missing.lock_shared();
    std::vector<uint32_t> stillMissing;
    /*for (auto wasMissing : vMissing) {
        if (mapExtra.count(wasMissing) == 0) {
            stillMissing.push_back(wasMissing);
        }
    }*/
    sm_missing.unlock_shared();
    sm_extra.unlock();


    if (stillMissing.size()) {
        std::cout << "Strange, it seems that " << stillMissing.size() << " positions are still missing.\n";
    }

    std::vector<bool> expectError(checksumSpec.size(), false);
    std::vector<uint8_t> checkInFlight(checksumSpec.size(), 0);
    for (int pos=start; pos<start+segmentLength; pos++) {
        if (vtx[pos] == NULL) {
            stillMissing.push_back(pos);
            std::cout << "Update: vtx[" << pos << "] still empty.\n";
            for (int i=0; i<checksumSpec.size(); i++) {expectError[i]=true;}
        } else {
            for (int i=0; i<checksumSpec.size(); i++) {
                checkInFlight[i] ^= *(vtx[pos]->GetId().end() - checksumSpec[i].first -1);
            }
        }

        for (int i=0; i<checksumSpec.size(); i++) {
            if ((pos+1) % (1<<checksumSpec[i].second) == 0 || pos == start+segmentLength-1) {
                int j = pos / (1<<checksumSpec[i].second);
                if (checksumData[i][j] != checkInFlight[i] && !expectError[i]) {
                    if (debug>3) std::cout << "Checksum error at pos " << pos << " interval " << (1<<checksumSpec[i].second) << "\n";
                    for (int k=pos-(1<<checksumSpec[i].second)+1; k<pos+1; k++) {
                        stillMissing.push_back(k);
                    }
                    for (int k=i+1; k<checksumSpec.size(); k++) {expectError[k]=true;}
                }
                else if (checksumData[i][j] == checkInFlight[i]) {
                    //std::cout << "Checksum match at pos " << pos << " interval " << (1<<checksumSpec[i].second) << "\n";
                }
                checkInFlight[i] = 0;
                expectError[i] = false;
            } else {
            //std::cout << "pos=" << pos << " i=" << i << " (pos+1) % (1<<checksumSpec[i].second) = " << ((pos+1) % (1<<checksumSpec[i].second)) << " expectError[i]=" << expectError[i] << "\n";
            }
        }
    }

    sm_missing.lock();
    vMissing.clear();
    for (auto miss : stillMissing) {
        vMissing.push_back(miss);
    }
    sm_missing.unlock();

    return 0;
}

XthinnerBlock::XthinnerBlock(const CBlock &block, const CTxMemPool &pool) : header(block) {
    txcount = block.vtx.size();
    segments.resize(1);
    extra_txns.resize(1);
    segments[0].FromTXIDs(block.vtx, pool, 0, block.vtx.size());
}

int XthinnerBlock::FillBlock(CBlock &block, const CTxMemPool &pool) {
    block.nVersion = header.nVersion;
    block.hashPrevBlock = header.hashPrevBlock;
    block.hashMerkleRoot = header.hashMerkleRoot;
    block.nTime = header.nTime;
    block.nBits = header.nBits;
    block.nNonce = header.nNonce;

    int result = 0;

    uint32_t totalSize = 0;
    for (int i=0; i < segments.size(); i++) totalSize += segments[i].size();
    block.vtx.resize(totalSize);

    uint32_t start = 0;
    for (int i=0; i<segments.size(); i++) {
        std::cout << "About to do segments[" << i << "].ToTXIDs(...)\n";
        result = segments[i].ToTXIDs(block.vtx, pool, start);
        if (result) {
            std::cout << "ToTXIDs returned status " << result << "\n";
            return result;
        }
        start += segments[i].size();
    }

    int nMissing = 0;
    for (int i=0; i<segments.size(); i++) {
        nMissing += segments[i].vMissing.size();
    }
    if (nMissing) {
        std::cout << "In FillBlock, " << nMissing << " transactions still missing or ambiguous\n";
    }
    return 0;
}

void XthinnerBlock::GetMissing(std::vector<std::vector<uint32_t> > &vvMissing) {
    vvMissing.clear();
    vvMissing.reserve(segments.size());
    for (auto seg : segments) {
        vvMissing.push_back(seg.vMissing);
    }
}

int XthinnerBlock::Update(CBlock &block, const std::vector<std::vector<PrefilledTransaction> > &extra) {
    int start = 0;
    for (int i=0; i<segments.size(); i++) {
        segments[i].Update(block.vtx, extra[i], start);
        start += segments[i].size();
    }
    return 0;
}

int FetchTxFromBlock(const CBlock &block, const std::vector<uint32_t> &vMissing, std::vector<PrefilledTransaction> &extra) {
    extra.clear();
    if (vMissing.size() > block.vtx.size()) {std::cout << "More missing than block size? " << block.vtx.size() << " " << vMissing.size() << "\n"; return 1;} // ain't nobody got time for that
    extra.resize(vMissing.size());
    for (int i=0; i<vMissing.size(); i++) {
        if (vMissing[i] > block.vtx.size()) {
            extra.clear();
            std::cout << "Error! Trying to fetch an index outside block size\n";
            return 1;
        }
        extra[i].index = vMissing[i];
        extra[i].tx = block.vtx[vMissing[i]];
    }
    std::cout << "Adding " << extra.size() << " extra transactions\n";
    return 0;
}

int FetchTxFromBlock(const CBlock &block, const std::vector<std::vector<uint32_t> > &vvMissing, std::vector<std::vector<PrefilledTransaction> > &vExtra) {
    vExtra.clear();
    vExtra.resize(vvMissing.size());
    std::cout << vvMissing[0].size() << " is the size of vvMissing[0]\n";
    int res;
    for (int i=0; i<vvMissing.size(); i++) {
        res = FetchTxFromBlock(block, vvMissing[i], vExtra[i]);
        if (res) {std::cout << "Uh oh! inner FetchTx errored!\n"; return res;}
    }
    return 0;
}