#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Copyright (c) 2019 The Ion Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C


#contrib/devtools/git-subtree-check.sh src/secp256k1
#contrib/devtools/git-subtree-check.sh src/univalue
#contrib/devtools/git-subtree-check.sh src/leveldb
test/lint/check-doc.py
#test/lint/check-rpc-mappings.py .
test/lint/lint-all.sh

if [ "$TRAVIS_EVENT_TYPE" = "pull_request" ]; then
    git log --merges --before="2 days ago" -1 --format='%H' > ./contrib/verify-commits/trusted-sha512-root-commit
    while read -r LINE; do travis_retry gpg --keyserver hkp://subset.pool.sks-keyservers.net --recv-keys $LINE; done < contrib/verify-commits/trusted-keys;
    #&& travis_wait 50 contrib/verify-commits/verify-commits.py --clean-merge=2;
fi
