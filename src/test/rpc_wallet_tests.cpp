// Copyright (c) 2013-2014 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "rpc/client.h"

#include "base58.h"
#include "wallet/wallet.h"

#include "test/test_ion.h"

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>


extern UniValue createArgs(int nRequired, const char* address1 = NULL, const char* address2 = NULL);
extern UniValue CallRPC(std::string args);

extern CWallet* pwalletMain;

BOOST_FIXTURE_TEST_SUITE(rpc_wallet_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(rpc_addmultisig)
{
    LOCK(pwalletMain->cs_wallet);

    rpcfn_type addmultisig = tableRPC["addmultisigaddress"]->actor;

    // old, 65-byte-long:
    const char address1Hex[] = "043e9a9b6c6909a36c582bd5c2468941ef7333b09f370ead462be01602cf665a9de133252c7c243b56d3501dc3aad579e68b47cd024a791c9a12c4152bf5b9bbab";
    // new, compressed:
    const char address2Hex[] = "03c947bfb537a29b9b4cadf1260d31adc2af77fb238220d1f987011e33a2a3a50a";

    UniValue v;
    CBitcoinAddress address;
    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(2, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_THROW(addmultisig(createArgs(0), false), std::runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1), false), std::runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(2, address1Hex), false), std::runtime_error);

    BOOST_CHECK_THROW(addmultisig(createArgs(1, ""), false), std::runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1, "NotAValidPubkey"), false), std::runtime_error);

    std::string short1(address1Hex, address1Hex + sizeof(address1Hex) - 2); // last byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short1.c_str()), false), std::runtime_error);

    std::string short2(address1Hex + 1, address1Hex + sizeof(address1Hex)); // first byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short2.c_str()), false), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_wallet)
{
    // Test RPC calls for various wallet statistics
    UniValue r;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CPubKey demoPubkey = pwalletMain->GenerateNewKey();
    CBitcoinAddress demoAddress = CBitcoinAddress(CTxDestination(demoPubkey.GetID()));
    UniValue retValue;
    std::string strAccount = "walletDemoAccount";
    std::string strPurpose = "receive";
    BOOST_CHECK_NO_THROW({ /*Initialize Wallet with an account */
        CWalletDB walletdb(pwalletMain->strWalletFile);
        CAccount account;
        account.vchPubKey = demoPubkey;
        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, strPurpose);
        walletdb.WriteAccount(strAccount, account);
    });

    CPubKey setaccountDemoPubkey = pwalletMain->GenerateNewKey();
    CBitcoinAddress setaccountDemoAddress = CBitcoinAddress(CTxDestination(setaccountDemoPubkey.GetID()));

    /*********************************
     * 			setaccount
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("setaccount " + setaccountDemoAddress.ToString() + " nullaccount"));
    /* iqVWhTRLbxtwHfxmZKDCsLmxfW8S5uqopjR is not owned by the test wallet. */
    BOOST_CHECK_THROW(CallRPC("setaccount iqVWhTRLbxtwHfxmZKDCsLmxfW8S5uqopjR nullaccount"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("setaccount"), std::runtime_error);
    /* iqVWhTRLbxtwHfxmZKDCsLmxfW8S5uqopj (33 chars) is an illegal address (should be 34 chars) */
    BOOST_CHECK_THROW(CallRPC("setaccount iqVWhTRLbxtwHfxmZKDCsLmxfW8S5uqopj nullaccount"), std::runtime_error);

    /*********************************
     * 			listunspent
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listunspent"));
    BOOST_CHECK_THROW(CallRPC("listunspent string"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 string"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 [] extra"), std::runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC("listunspent 0 1 []"));
    BOOST_CHECK(r.get_array().empty());

    /*********************************
     * 		listreceivedbyaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress"));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress not_int"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 not_bool"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0 true"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 true extra"), std::runtime_error);

    /*********************************
     * 		listreceivedbyaccount
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount"));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount 0"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount not_int"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount 0 not_bool"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount 0 true"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount 0 true extra"), std::runtime_error);

    /*********************************
     * 		getrawchangeaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getrawchangeaddress"));

    /*********************************
     * 		getnewaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress"));
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress getnewaddress_demoaccount"));

    /*********************************
     * 		getaccountaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getaccountaddress \"\""));
    BOOST_CHECK_NO_THROW(CallRPC("getaccountaddress accountThatDoesntExists")); // Should generate a new account
    BOOST_CHECK_NO_THROW(retValue = CallRPC("getaccountaddress " + strAccount));
    BOOST_CHECK(CBitcoinAddress(retValue.get_str()).Get() == demoAddress.Get());

    /*********************************
     * 			getaccount
     *********************************/
    BOOST_CHECK_THROW(CallRPC("getaccount"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("getaccount " + demoAddress.ToString()));

    /*********************************
     * 	signmessage + verifymessage
     *********************************/
    BOOST_CHECK_NO_THROW(retValue = CallRPC("signmessage " + demoAddress.ToString() + " mymessage"));
    BOOST_CHECK_THROW(CallRPC("signmessage"), std::runtime_error);
    /* Should throw error because this address is not loaded in the wallet */
    BOOST_CHECK_THROW(CallRPC("signmessage ifjbVcbSwdYtPcEjGnwkvSn1EJ8d3mSxbE mymessage"), std::runtime_error);

    /* missing arguments */
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress.ToString()), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str()), std::runtime_error);
    /* Illegal address */
    //BOOST_CHECK_THROW(CallRPC("verifymessage iqVWhTRLbxtwHfxmZKDCsLmxfW8S5uqopj " + retValue.get_str() + " mymessage"), std::runtime_error);
    /* wrong address */
    BOOST_CHECK(CallRPC("verifymessage ifjbVcbSwdYtPcEjGnwkvSn1EJ8d3mSxbE " + retValue.get_str() + " mymessage").get_bool() == false);
    /* Correct address and signature but wrong message */
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str() + " wrongmessage").get_bool() == false);
    /* Correct address, message and signature*/
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str() + " mymessage").get_bool() == true);

    /*********************************
     * 		getaddressesbyaccount
     *********************************/
    BOOST_CHECK_THROW(CallRPC("getaddressesbyaccount"), std::runtime_error);
    BOOST_CHECK_NO_THROW(retValue = CallRPC("getaddressesbyaccount " + strAccount));
    UniValue arr = retValue.get_array();
    BOOST_CHECK(arr.size() > 0);
    BOOST_CHECK(CBitcoinAddress(arr[0].get_str()).Get() == demoAddress.Get());
}

BOOST_AUTO_TEST_SUITE_END()
