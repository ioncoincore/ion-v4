// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokens/tokengroupdescription.h"
#include "util.h"

// Returns true if the first 5 bytes indicate the script contains a Token Group Description
// Output descriptionData[] holds 0 or more unverified char vectors of description data
bool CTokenGroupDescription::BuildGroupDescData(const CScript& script, std::vector<std::vector<unsigned char> > &descriptionData) {
    std::vector<std::vector<unsigned char> > desc;

    CScript::const_iterator pc = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;

    // 1 byte
    if (!script.GetOp(pc, opcode, data)) return false;
    if (opcode != OP_RETURN) return false;

    // 1+4 bytes
    if (!script.GetOp(pc, opcode, data)) return false;
    uint32_t OpRetGroupId;
    if (data.size()!=4) return false;
    // Little Endian
    OpRetGroupId = (uint32_t)data[3] << 24 | (uint32_t)data[2] << 16 | (uint32_t)data[1] << 8 | (uint32_t)data[0];
    if (OpRetGroupId != 88888888) return false;

    while (script.GetOp(pc, opcode, data)) {
        LogPrint("token", "Token description data: opcode=[%d] data=[%s]\n", opcode, std::string(data.begin(), data.end()));
        desc.emplace_back(data);
    }
    descriptionData = desc;
    return true;
}

// Returns true if the token description data fields have the correct maximum length
// On success, *this is initialized with the data fields
bool CTokenGroupDescription::SetGroupDescData(const std::vector<std::vector<unsigned char> > descriptionData) {

    auto it = descriptionData.begin();

    if (it == descriptionData.end()) return false;

    try {
        strTicker = GetStringFromChars(*it, 10); // Max 11 bytes (1+10)
        it++;

        if (it == descriptionData.end()) return false;
        strName = GetStringFromChars(*it, 30); // Max 31 bytes (1+30)
        it++;

        if (it == descriptionData.end()) return false;
        if ((*it).size() != 2) return false;
        nDecimalPos = (uint8_t)(*it)[0]; // Max 3 bytes
        it++;

        if (it == descriptionData.end()) return false;
        strDocumentUrl = GetStringFromChars(*it, 98); // Max 101 bytes (2+98)
        it++;

        if (it == descriptionData.end()) return false;

        documentHash = uint256(*it); // Max 33 bytes (1+32)
    } catch (...) {
        return false;
    }

    return true;
}
