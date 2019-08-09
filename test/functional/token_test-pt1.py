#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the functionality of all CLI commands.

"""
from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import *

from time import sleep
from decimal import Decimal

import re
import sys
import os
import subprocess

ION_TX_FEE = 0.001
ION_AUTH_ADDR = "gAQQQjA4DCT2EZDVK6Jae4mFfB217V43Nt"

class TokenTest (BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        #self.extra_args = [["-debug"],["-debug"]]

    def run_test(self):
        tmpdir=self.options.tmpdir
        #connect_nodes_bi(self.nodes,0,1)
        self.log.info("Importing Private Key")
        self.nodes[0].importprivkey('cUnScAFQYLW8J8V9bWr57yj2AopudqTd266s6QuWGMMfMix3Hff4')
        self.log.info("Mining Blocks...")
        self.nodes[0].generate(261)
        self.log.info("Block Count Node 0 %s" % self.nodes[0].getblockcount())
        self.log.info("Send to address %s %s" % (ION_AUTH_ADDR, self.nodes[0].sendtoaddress(ION_AUTH_ADDR, 1)))
        self.log.info("Send to address %s %s" % (ION_AUTH_ADDR, self.nodes[0].sendtoaddress(ION_AUTH_ADDR, 1)))
        self.log.info("Send to address %s %s" % (ION_AUTH_ADDR, self.nodes[0].sendtoaddress(ION_AUTH_ADDR, 1)))
        self.log.info("Accounts %s" % self.nodes[0].listaddressgroupings())
        self.nodes[0].generate(6)
        #post_transaction(self, "gAQQQjA4DCT2EZDVK6Jae4mFfB217V43Nt")
        # try creating tokens without mgmt addresses
        try:
            self.nodes[0].token('mint', AtomGroup_ID, mintaddr, '100')
        except Exception as e:
            self.log.info("Error: No management token")
            self.log.info(e)
        magicTok=self.nodes[0].managementtoken('new', 'MAGIC', 'MagicToken', '4', 'https://wiki.lspace.org/mediawiki/Magic', '0')
        self.nodes[0].generate(1)
        MagicGroup_ID= magicTok['groupIdentifier']
        self.nodes[0].token('mint', MagicGroup_ID, ION_AUTH_ADDR, 25)
        self.nodes[0].generate(1)
        XDMTok=self.nodes[0].managementtoken('new', 'XDM', 'DarkMatter', '13', 'https://www.darkmatter.info/', '0')
        self.nodes[0].generate(1)
        XDMGroup_ID= XDMTok['groupIdentifier']
        AtomTok=self.nodes[0].managementtoken('new', 'ATOM', 'Atom', '0', 'https://www.ionomy.com/', '0')
        self.nodes[0].generate(1)
        AtomGroup_ID= AtomTok['groupIdentifier']
        self.log.info("Token Info %s" % json.dumps(self.nodes[0].tokeninfo("all"), indent=4))
        mintaddr=self.nodes[0].getnewaddress()
        self.nodes[0].token('mint', MagicGroup_ID, mintaddr, '4975')
        self.nodes[0].generate(1)
        try:
            self.nodes[0].token('mint', XDMGroup_ID, mintaddr, '0')
        except Exception as e:
            self.log.info("Error: No XDM")
            self.log.info(e)
        self.nodes[0].token('mint', XDMGroup_ID, mintaddr, '71')
        self.nodes[0].generate(1)
        self.nodes[0].token('mint', AtomGroup_ID, mintaddr, '100')
        self.nodes[0].generate(1)
        tokenBalance=self.nodes[0].token('balance')
        for balance in tokenBalance:
            self.log.info("Token Name %s" % balance['name'])
            self.log.info("Token Balance %s" % balance['balance'])
        self.log.info("XDM Ticker %s" % json.dumps(self.nodes[0].tokeninfo('ticker', 'XDM'), indent=4))
        self.log.info("XDM Scan Tokens %s" % self.nodes[0].scantokens('start', XDMGroup_ID))   
        XDMAuth=self.nodes[0].token('listauthorities')
        XDMAuth_vout=XDMAuth[0]['vout']
        XDMAuth_txid=XDMAuth[0]['txid']
        self.log.info("Drop Authorities %s" % self.nodes[0].token('dropauthorities', XDMGroup_ID, XDMAuth_txid, str(XDMAuth_vout), 'mint'))
        self.nodes[0].generate(1)
        self.log.info("XDM Scan Tokens %s" % self.nodes[0].scantokens('start', XDMGroup_ID))
        tokenBalance=self.nodes[0].token('balance')
        for balance in tokenBalance:
            self.log.info("Token Name %s" % balance['name'])
            self.log.info("Token Balance %s" % balance['balance'])
        try:
            self.nodes[0].token('mint', XDMGroup_ID, mintaddr, '100')
        except Exception as e:
            self.log.info("Error: No mint flag")
            self.log.info(e)
        self.log.info("Token info all %s" % json.dumps(self.nodes[0].tokeninfo('all'), indent=4))
        self.log.info("Token info ticker XDM %s" % json.dumps(self.nodes[0].tokeninfo('ticker', 'XDM'), indent=4))
        self.log.info("Token info name DarkMatter %s" % json.dumps(self.nodes[0].tokeninfo('name', 'darkmatter'), indent=4))
        self.log.info("Token info groupid %s %s" % (XDMGroup_ID, json.dumps(self.nodes[0].tokeninfo('groupid', XDMGroup_ID), indent=4)))
if __name__ == '__main__':
    TokenTest().main()