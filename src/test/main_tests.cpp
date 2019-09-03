// Copyright (c) 2014-2019 The Bitcoin Core developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018-2019 The Ion developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"
#include "main.h"
#include "test_ion.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

CAmount nMoneySupplyPoWEnd = 16629951 * COIN;


BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    /*
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 1; nHeight += 1) {
        // premine in block 1 173,360,471 ION)
        CAmount nSubsidy = GetBlockValue(nHeight);
        BOOST_CHECK(nSubsidy <= 0 * COIN);
        nSum += nSubsidy;
    }

    for (int nHeight = 1; nHeight < 2; nHeight += 1) {
        //PoW Phase One
        CAmount nSubsidy = GetBlockValue(nHeight);
        BOOST_CHECK(nSubsidy <= 16400000 * COIN);
        nSum += nSubsidy;
    }

    for (int nHeight = 2; nHeight < 3; nHeight += 1) {
        //PoW Phase One
        CAmount nSubsidy = GetBlockValue(nHeight);
        BOOST_CHECK(nSubsidy <= 0 * COIN);
        nSum += nSubsidy;
    }

    for (int nHeight = 3; nHeight < 455; nHeight += 1) {
        //PoW Phase Two
        CAmount nSubsidy = GetBlockValue(nHeight);
        BOOST_CHECK(nSubsidy <= 0 * COIN);
        nSum += nSubsidy;
    }

    for (int nHeight = 455; nHeight < 1001; nHeight += 1) {
        //PoW Phase Two
        CAmount nSubsidy = GetBlockValue(nHeight);
        BOOST_CHECK(nSubsidy <= 23 * COIN);
        BOOST_CHECK(MoneyRange(nSubsidy));
        nSum += nSubsidy;
        BOOST_CHECK(nSum > 0 && nSum <= nMoneySupplyPoWEnd);
    }
    // BOOST_CHECK(nSum == 1662995400000000ULL);
    */
}

BOOST_AUTO_TEST_SUITE_END()
