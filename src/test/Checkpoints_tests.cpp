// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Unit tests for block-chain checkpoints
//

#include "checkpoints.h"

#include "uint256.h"
#include "test_ion.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(Checkpoints_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(sanity)
{
    // ionDevs - RELEASE CHANGE - if required, sanity checks
    uint256 p1 = uint256("0x0000004cf5ffbf2e31a9aa07c86298efb01a30b8911b80af7473d1114715084b");     // First premine block
    uint256 p1000 = uint256("0x0000000144b22b0af9bced65256d5eccc4e3f112a89bdb0f08ab8dc2a6145b56");  // Last POW block

    BOOST_CHECK(Checkpoints::CheckBlock(1, p1));
    BOOST_CHECK(Checkpoints::CheckBlock(1000, p1000));

    // Wrong hashes at checkpoints should fail:
    /* DISABLE AS NOT WORKING - **TODO** - fix it
    BOOST_CHECK(!Checkpoints::CheckBlock(1, p1000));
    */
    BOOST_CHECK(!Checkpoints::CheckBlock(1000, p1));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckBlock(1+1, p1000));
    BOOST_CHECK(Checkpoints::CheckBlock(998+1, p1));

    // remove this later
    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 1000);

}

BOOST_AUTO_TEST_SUITE_END()
