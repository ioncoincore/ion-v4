#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

from test_framework.util import *
from test_framework.test_framework import BitcoinTestFramework
import logging
import pprint
import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
logging.basicConfig(format='%(asctime)s.%(levelname)s: %(message)s', level=logging.INFO, stream=sys.stdout)


class MyTest (BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir)

        # Now interconnect the nodes
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        self.is_network_split = False
        self.sync_all()

    def checkGroupNew(self, txjson):
        hasGroupOutput = 0
        groupFlags = 0
        for t in txjson["vout"]:
            asm = t["scriptPubKey"]["asm"].split()
            assert(len(asm) > 0)  # output script must be something

            if asm[2] == "OP_GROUP":
                hasGroupOutput += 1
                groupFlags = int(asm[1], 16)

        assert(hasGroupOutput == 1)
        assert(groupFlags > (1 >> 63))  # verify group bit set

    def examineTx(self, tx, node):
        txjson = node.decoderawtransaction(node.gettransaction(tx)["hex"])
        i = 0
        for txi in txjson["vin"]:
            txiJson = node.decoderawtransaction(node.gettransaction(txi["txid"])["hex"])
            prevOut = txiJson["vout"][txi["vout"]]
            print("prevout %d:\n" % i)
            pprint.pprint(prevOut, indent=2, width=200)
            i += 1
        print("\n")
        pprint.pprint(txjson, indent=2, width=200)
        print("\n")

    def run_test(self):

        logging.info("This is a template for you to use when making new tests")

        # generate enough blocks so that nodes[0] has a balance
        self.nodes[2].generate(2)
        self.sync_blocks()
        self.nodes[0].generate(101)
        self.sync_blocks()

        assert_equal(self.nodes[0].getbalance(), 50)

        try:
            ret = self.nodes[1].token("new")
            assert(0)  # should have raised exception
        except JSONRPCException as e:
            assert("No coins available" in e.error["message"])

        auth2Addr = self.nodes[2].getnewaddress()
        auth1Addr = self.nodes[1].getnewaddress()
        auth0Addr = self.nodes[0].getnewaddress()

        try:
            ret = self.nodes[1].token("new", auth1Addr)
            assert(0)  # should have raised exception
        except JSONRPCException as e:
            assert("No coins available" in e.error["message"])

        # Create a group, allow wallet to pick an authority address
        t = self.nodes[0].token("new")
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grpId = t["groupIdentifier"]

        # Create a group to a specific authority address
        t = self.nodes[0].token("new", auth0Addr)
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grp0Id = t["groupIdentifier"]

        # Create a group on behalf of a different node (with an authority address I don't control)
        t = self.nodes[0].token("new", auth1Addr)
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grp1Id = t["groupIdentifier"]

        t = self.nodes[0].token("new", auth2Addr)
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grp2Id = t["groupIdentifier"]

        mint0_0 = self.nodes[0].getnewaddress()
        mint0_1 = self.nodes[0].getnewaddress()
        mint1_0 = self.nodes[1].getnewaddress()
        mint2_0 = self.nodes[2].getnewaddress()
        # mint to a local address
        self.nodes[0].token("mint", grpId, mint0_0, 1000)
        # mint to a local address
        self.nodes[0].token("mint", grpId, mint0_0, 1000)
        # mint to a foreign address
        self.nodes[0].token("mint", grpId, mint1_0, 1000)

        # mint but node does not have authority
        try:
            self.nodes[0].token("mint", grp2Id, mint0_0, 1000)
        except JSONRPCException as e:
            assert("To mint coins, an authority output with mint capability is needed." in e.error["message"])

        # mint but node does not have anything to spend
        try:
            self.nodes[1].token("mint", grp1Id, mint0_0, 1000)
        except JSONRPCException as e:
            assert("To mint coins, an authority output with mint capability is needed." in e.error["message"])

        # mint from node 2 of group created by node 0 on behalf of node 2
        self.sync_all()  # node 2 has to be able to see the group new tx that node 0 made
        assert(self.nodes[2].token("balance", grp2Id) == 0)
        tx = self.nodes[2].token("mint", grp2Id, mint2_0, 1000)
        txjson = self.nodes[2].decoderawtransaction(self.nodes[2].getrawtransaction(tx))

        tx = self.nodes[2].token("mint", grp2Id, mint0_0, 100)
        assert(self.nodes[2].token("balance", grp2Id) == 1000)  # check proper token balance
        self.sync_all()  # node 0 has to be able to see the mint tx that node 2 made
        assert(self.nodes[0].token("balance", grp2Id) == 100)   # on both nodes
        tx = self.nodes[2].token("mint", grp2Id, mint0_0, 100)
        self.sync_all()  # node 0 has to be able to see the mint tx that node 2 made
        assert(self.nodes[0].token("balance", grp2Id, mint0_0) == 200)
        # check that a different token group doesn't count toward balance
        tx = self.nodes[0].token("mint", grpId, mint0_0, 1000)
        assert(self.nodes[0].token("balance", grp2Id, mint0_0) == 200)

        try:  # melt without authority
            self.nodes[0].token("melt", grp2Id, 200)  # I should not be able to melt without authority
            assert(0)
        except JSONRPCException as e:
            print(e.error["message"])
            assert("To melt coins, an authority output with melt capability is needed." in e.error["message"])
            pass

        try:  # melt too much
            self.nodes[2].token("melt", grp2Id, 2000)
            assert(0)
        except JSONRPCException as e:
            assert("Not enough tokens in the wallet." in e.error["message"])

        self.nodes[2].token("melt", grp2Id, 100)
        assert(self.nodes[2].token("balance", grp2Id) == 900)

        try:  # send too much
            self.nodes[2].token("send", grp2Id, mint0_0, 1000)
            assert(0)
        except JSONRPCException as e:
            assert("Not enough tokens in the wallet." in e.error["message"])

        assert(self.nodes[2].token("balance", grp2Id) == 900)
        tx = self.nodes[2].token("send", grp2Id, mint0_0, 100)
        self.examineTx(tx, self.nodes[2])
        self.sync_all()
        assert(self.nodes[0].token("balance", grp2Id, mint0_0) == 300)
        assert(self.nodes[2].token("balance", grp2Id) == 800)

        # pdb.set_trace()


if __name__ == '__main__':
    MyTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        # "debug": ["blk", "thin", "mempool", "bench", "evict"],
        "debug": ["mempool"],
        "blockprioritysize": 2000000,  # we don't want any transactions rejected due to insufficient fees...
        "mining.opgroup": 1
    }

    # you may want these additional flags:
    # "--srcdir=<out-of-source-build-dir>/debug/src"
    # "--tmpdir=/ramdisk/test"
    t.main(["--nocleanup", "--noshutdown", "--tmpdir=/ramdisk/test"], bitcoinConf, None)
