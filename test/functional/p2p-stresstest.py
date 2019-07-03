#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Copyright (c) 2017 The Bitcoin developers
# Copyright (c) 2019 The Bitcoin ABC developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    BlockTransactions,
    BlockTransactionsRequest,
    calculate_shortid,
    CBlock,
    CBlockHeader,
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    HeaderAndShortIDs,
    msg_block,
    msg_blocktxn,
    msg_cmpctblock,
    msg_getblocktxn,
    msg_getdata,
    msg_getheaders,
    msg_headers,
    msg_inv,
    msg_sendcmpct,
    msg_sendheaders,
    msg_tx,
    msg_xtrconfig,
    msg_xtrblk,
    NODE_NETWORK,
    P2PHeaderAndShortIDs,
    PrefilledTransaction,
    ToHex,
)
from test_framework.mininode import (
    mininode_lock,
    network_thread_start,
    P2PInterface,
)
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal, sync_blocks, wait_until
import time, threading, traceback, http, sys
from decimal import Decimal

'''
stresstest -- test spam generation and localhost block propagation
'''

NUM_NODES = 4
# 168k tx is 32 MB
TX_PER_BLOCK = 168000 
# set this below your hardware's peak generation rate if you want
# to have transaction validation happen in parallel with generation,
# or if you otherwise want to simulate lower generation rates.
MAX_GENERATION_RATE_PER_NODE = 15000 

# TestNode: A peer we use to send messages to bitcoind, and store responses.

class TestNode(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_xtrconfig = []
        self.block_announced = False
        # Store the hashes of blocks we've seen announced.
        # This is for synchronizing the p2p message traffic,
        # so we can eg wait until a particular block is announced.
        self.announced_blockhashes = set()

    def on_xtrconfig(self, message):
        self.last_xtrconfig.append(message)

    def on_xtrblk(self, message):
        self.block_announced = True
        self.last_message["xtrblk"].xthinner_block.header.calc_sha256()
        self.announced_blockhashes.add(
            self.last_message["xtrblk"].xthinner_block.header.sha256)

    def on_headers(self, message):
        self.block_announced = True
        for x in self.last_message["headers"].headers:
            x.calc_sha256()
            self.announced_blockhashes.add(x.sha256)

    def on_inv(self, message):
        for x in self.last_message["inv"].inv:
            if x.type == 2:
                self.block_announced = True
                self.announced_blockhashes.add(x.hash)

    # Requires caller to hold mininode_lock
    def received_block_announcement(self):
        return self.block_announced

    def clear_block_announcement(self):
        with mininode_lock:
            self.block_announced = False
            self.last_message.pop("inv", None)
            self.last_message.pop("headers", None)
            self.last_message.pop("xtrblk", None)

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.send_message(msg)

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_message(headers_message)

    def request_headers_and_sync(self, locator, hashstop=0):
        self.clear_block_announcement()
        self.get_headers(locator, hashstop)
        wait_until(self.received_block_announcement,
                   timeout=30, lock=mininode_lock)
        self.clear_block_announcement()

    # Block until a block announcement for a particular block hash is
    # received.
    def wait_for_block_announcement(self, block_hash, timeout=30):
        def received_hash():
            return (block_hash in self.announced_blockhashes)
        wait_until(received_hash, timeout=timeout, lock=mininode_lock)

    def send_await_disconnect(self, message, timeout=30):
        """Sends a message to the node and wait for disconnect.

        This is used when we want to send a message into the node that we expect
        will get us disconnected, eg an invalid block."""
        self.send_message(message)
        wait_until(lambda: not self.connected,
                   timeout=timeout, lock=mininode_lock)


class StressTest(BitcoinTestFramework):
    def set_test_params(self, xthinner='1'):
        self.setup_clean_chain = True
        self.num_nodes = NUM_NODES
        self.extra_args = [["-usexthinner=%s"%xthinner, 
                            "-blockmaxsize=32000000", 
                            "-checkmempool=0", 
                            "-debugexclude=net", 
                            #"-fastwallet=1",
                            #"-debugexclude=wallet", 
                            "-debugexclude=mempool"]]* self.num_nodes
        self.utxos = []

    def build_block_on_tip(self, node):
        height = node.getblockcount()
        tip = node.getbestblockhash()
        mtp = node.getblockheader(tip)['mediantime']
        block = create_block(
            int(tip, 16), create_coinbase(height + 1), mtp + 1)
        block.nVersion = 4
        block.solve()
        return block

    # Create 10 more anyone-can-spend utxo's for testing.
    def make_utxos(self, target=10000):
        print("Running make_utxos()...")
        rootamount = 49.0/len(self.nodes)
        fanout = 1000 if target < 1000*50 else target // 50
        num_stages = -(-target // fanout) +1 # rounds up
        print("Fanout=%i, num_stages=%i" % (fanout, num_stages))
        self.nodes[0].generate(101)
        self.nodes[0].generate(num_stages * self.num_nodes-1)
        time.sleep(0.2)
        self.nodes[0].generate(1)
        addresses = [node.getnewaddress() for node in self.nodes]
        node_addresses = [[] for _ in self.nodes]
        self.node_addresses = node_addresses
        t0 = time.time()
        def get_addresses(node, addresslist, n):
            for _ in range(n):
                addresslist.append(node.getnewaddress())
        threads = [threading.Thread(target=get_addresses, 
                                    args=(self.nodes[i], node_addresses[i], fanout)) 
                   for i in range(len(self.nodes))]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        t1 = time.time(); print("Generating addresses took %3.3f sec" % (t1-t0))
        sync_blocks(self.nodes, timeout=10)
        for i in range(self.num_nodes-1, 0, -1):
            amount = Decimal(round(rootamount/(fanout+1) * 1e8)) / Decimal(1e8)
            payments = {node_addresses[i][n]:amount for n in range(fanout)}
            t1 = time.time()
            for stage in range(num_stages):
                self.nodes[0].sendmany('', payments)
            t2 = time.time(); print("Filling node wallets took %3.3f sec for stage %i:%i" % (t2-t1, i, stage))
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)
        for i in range(1+(target*self.num_nodes)//20000):
            self.nodes[0].generate(1)
            sync_blocks(self.nodes, timeout=20)
            blk = self.nodes[0].getblock(self.nodes[0].getbestblockhash(), 1)
            print("Block has %i transactions and is %i bytes" % (len(blk['tx']), blk['size']))
        return amount

    def check_mempools(self):
        results = []
        for node in self.nodes:
            success = False
            while not success:
                try:
                    res = node.getmempoolinfo()
                    results.append(res)
                    success = True
                except:
                    time.sleep(0.001)
        print("Mempool sizes:\t", ("%7i "*len(self.nodes)) % tuple([r['size'] for r in results]), '\t',
              "Mempool bytes:\t", ("%9i "*len(self.nodes)) % tuple([r['bytes'] for r in results]))
        return [r['size'] for r in results]


    def mempool_watcher(self, interval):
        self.watching=True
        while self.watching:
            time.sleep(interval)
            self.check_mempools()

    def generate_spam(self, value, txcount):
        def helper(node, count, rate=100):
            t = time.time()
            addresses = self.node_addresses[node]
            for i in range(0, count, 100):
                now = time.time()
                if i/(now-t) > rate:
                    time.sleep(i/rate - (now-t))
                if not (i%5000):
                    print("Node %2i\ttx %5i\tat %3.3f sec\t(%3.0f tx/sec)" % (node, i, time.time()-t, (i/(time.time()-t))))
                add = addresses[i % len(addresses)]
                try:
                    self.nodes[node].sendtoaddress(add, value, '', '', False, 100)
                except http.client.CannotSendRequest:
                    self.nodes[node].sendtoaddress(add, value, '', '', False, 100)
                except:
                    print("Node %i had a fatal error on tx %i:" % (node, i))
                    traceback.print_exc()
                    break
        threads = [threading.Thread(target=helper, args=(n, txcount, MAX_GENERATION_RATE_PER_NODE))
                   for n in range(1, len(self.nodes))]

        t0 = time.time()
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        t1 = time.time(); print("Generating spam took %3.3f sec for %i tx (total %4.0f tx/sec)" \
            % (t1-t0, (self.num_nodes-1)*txcount, (self.num_nodes-1)*txcount/(t1-t0)))
        startresults = results = self.check_mempools()
        onedone = False
        while [r for r in results if abs(r - results[0]) > 10]:
            time.sleep(1)
            results = self.check_mempools()
            if not onedone and [r for r in results if abs(r - txcount * (self.num_nodes-1)) < 10]:
                finishresults = results
                t1b = time.time()
                onedone = True
        t2 = time.time(); print("Mempool sync took %3.3f sec" % (t2-t1))
        deltas = [r-s for r,s in zip(finishresults, startresults)]
        print("Per-node ATMP tx/sec: " + ("\t%4.0f" * self.num_nodes) % tuple([d/(t1b-t1) for d in deltas]))
        print("Average mempool sync rate: \t%4.0f tx/sec" % (sum(deltas)/(t1b-t1)/len(deltas)))

        for i in range(2):
            t2a = time.time()
            oldheight = self.nodes[0].getblockcount()
            if not i: print("Generating block ", end="")
            self.nodes[0].generate(1)
            t2b = time.time()
            if not i: print("took %3.3f sec" % (t2b-t2a))
            for n in range(self.num_nodes):
                while self.nodes[n].getblockcount() == oldheight:
                    time.sleep(0.05)
                t2c = time.time()
                if not i: print("%i:%6.3f   " % (n, t2c-t2b), end="")
            if not i: print()
            sync_blocks(self.nodes, timeout=180)
            t2c = time.time()
            if not i: print("Propagating block took %3.3f sec -- %3.3f sec per hop" % (t2c-t2b, (t2c-t2b)/(self.num_nodes-1)))
            blk = self.nodes[0].getblock(self.nodes[0].getbestblockhash(), 1)
            if not i: print("Block has %i transactions and is %i bytes" % (len(blk['tx']), blk['size']))



    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        #self.test_node = self.nodes[0].add_p2p_connection(TestNode())

        network_thread_start()
        self.log.info("Running tests:")


        watcher = threading.Thread(target=self.mempool_watcher, args=(5,))
        # watcher.start()
        print(self.nodes[0].getmempoolinfo())

        tx_per_node = int(TX_PER_BLOCK/(self.num_nodes-1))
        # We will need UTXOs to construct transactions in later tests.
        utxo_value = self.make_utxos(tx_per_node)
        spend_value = utxo_value
            
        for i in range(5):
            spend_value = Decimal((spend_value * 100000000 - 192)) / Decimal(1e8)
            print("Spam block generation round %i" % i)
            self.generate_spam(spend_value, txcount=int(tx_per_node))

        self.watching = False
        # watcher.join()


if __name__ == '__main__':
    if not [arg for arg in sys.argv if arg.startswith('--walletdir')]:
        print("\n\nThis test will be slow at generating transactions unless " +
            "you have a very fast SSD or a ramdisk for the wallet files.\n" +
            "It is strongly recommended to use a ramdisk for the wallets. You can set that "
            "up on Linux with this:\n\n"
            "sudo mount -t tmpfs size=2G /tmp/tmpfs/\n" +
            "python3 p2p-stresstest.py --walletdir=/tmp/tmpfs/test0\n\n\n")
    StressTest().main()
