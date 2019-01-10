// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <algorithm>
#include "coins.h"
#include "consensus/tokengroups.h"
#include "dstencode.h"
#include "init.h"
#include "main.h"
#include "coincontrol.h"
#include "primitives/transaction.h"
#include "rpc/protocol.h"
#include "script/script.h"
#include "script/standard.h"
#include "pubkey.h"
#include "ionaddrenc.h"
#include "random.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"

#include <unordered_map>
#include <univalue.h>

CTokenGroupID NoGroup; // No group specified.

bool IsAnyTxOutputGrouped(const CTransaction &tx)
{
    for (const CTxOut &txout : tx.vout)
    {
        CTokenGroupInfo grp(txout.scriptPubKey);
        if (grp.invalid)
            return true; // Its still grouped even if invalid
        if (grp.associatedGroup != NoGroup)
            return true;
    }

    return false;
}

std::vector<unsigned char> SerializeAmount(CAmount num)
{
    CDataStream strm(SER_NETWORK, CLIENT_VERSION);
    if (num < 0) // negative numbers are serialized at full length
    {
        int64_t xSize = num;
        WRITEDATA(strm, xSize);
    }
    else if (num < 256)
    {
        unsigned char chSize = num;
        WRITEDATA(strm, chSize);
//        ser_writedata8(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned short>::max())
    {
        unsigned short xSize = num;
        WRITEDATA(strm, xSize);
//        ser_writedata16(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned int>::max())
    {
        unsigned int xSize = num;
        WRITEDATA(strm, xSize);
//        ser_writedata32(strm, num);
    }
    else
    {
        uint64_t xSize = num;
        WRITEDATA(strm, xSize);
//        ser_writedata64(strm, num);
    }
    return std::vector<unsigned char>(strm.begin(), strm.end());
}

CAmount DeserializeAmount(std::vector<unsigned char> &vec)
{
    int sz = vec.size();
    if (sz == 1)
    {
        return vec[0];
    }
    CDataStream strm(vec, SER_NETWORK, CLIENT_VERSION);
    if (sz == 2)
    {
        unsigned short xSize;
        READDATA(strm, xSize);
        return xSize;
//        return ser_readdata16(strm);
    }
    if (sz == 4)
    {
        unsigned int xSize;
        READDATA(strm, xSize);
        return xSize;
//        return ser_readdata32(strm);
    }
    if (sz == 8)
    {
        uint64_t v;
        READDATA(strm, v);
//        uint64_t v = ser_readdata64(strm);
        return (CAmount) v;
    }
    throw std::ios_base::failure("DeserializeAmount(): invalid format");
}

#if 0
CTokenGroupID ExtractControllingGroup(const CScript &scriptPubKey)
{
    txnouttype whichType;
    typedef std::vector<unsigned char> valtype;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return CTokenGroupID();

    // only certain well known script types are allowed to mint or melt
    if ((whichType == TX_PUBKEYHASH) || (whichType == TX_GRP_PUBKEYHASH) || (whichType == TX_SCRIPTHASH) ||
        (whichType == TX_GRP_SCRIPTHASH))
    {
        return CTokenGroupID(uint160(vSolutions[0]));
    }
    return CTokenGroupID();
}
#endif

CTokenGroupInfo::CTokenGroupInfo(const CScript &script)
    : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(false)
{
    CScript::const_iterator pc = script.begin();
    std::vector<unsigned char> groupId;
    std::vector<unsigned char> tokenQty;
    std::vector<unsigned char> data;
    opcodetype opcode;
    opcodetype opcodeGrp;
    opcodetype opcodeQty;

    // mintMeltGroup = ExtractControllingGroup(script);

    if (!script.GetOp(pc, opcodeGrp, groupId))
    {
        associatedGroup = NoGroup;
        return;
    }

    if (!script.GetOp(pc, opcodeQty, tokenQty))
    {
        associatedGroup = NoGroup;
        return;
    }

    if (!script.GetOp(pc, opcode, data))
    {
        associatedGroup = NoGroup;
        return;
    }

    if (opcode != OP_GROUP)
    {
        associatedGroup = NoGroup;
        return;
    }
    else // If OP_GROUP is used, enforce rules on the other fields
    {
        // group must be 32 bytes
        if (opcodeGrp != 0x20)
        {
            invalid = true;
            return;
        }
        // quantity must be 1, 2, 4, or 8 bytes
        if ((opcodeQty != 1) && (opcodeQty != 2) && (opcodeQty != 4) && (opcodeQty != 8))
        {
            invalid = true;
            return;
        }
    }

    try
    {
        quantity = DeserializeAmount(tokenQty);
    }
    catch (std::ios_base::failure &f)
    {
        invalid = true;
    }
    if (quantity < 0)
    {
        controllingGroupFlags = (GroupAuthorityFlags)quantity;
    }
    associatedGroup = groupId;
}


// local class that just keeps track of the amounts of each group coming into and going out of a transaction
class CBalance
{
public:
    CBalance()
        : ctrlPerms(GroupAuthorityFlags::NONE), allowedCtrlOutputPerms(GroupAuthorityFlags::NONE),
          ctrlOutputPerms(GroupAuthorityFlags::NONE), input(0), output(0), numOutputs(0)
    {
    }
    CTokenGroupInfo groups; // possible groups
    GroupAuthorityFlags ctrlPerms; // what permissions are provided in inputs
    GroupAuthorityFlags allowedCtrlOutputPerms; // What permissions are provided in inputs with CHILD set
    GroupAuthorityFlags ctrlOutputPerms; // What permissions are enabled in outputs
    CAmount input;
    CAmount output;
    uint64_t numOutputs;
};

bool CheckTokenGroups(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &view)
{
    std::unordered_map<CTokenGroupID, CBalance> gBalance;
    // This is an optimization allowing us to skip single-mint hashes if there are no output groups
    bool anyOutputGroups = false;
    bool anyOutputControlGroups = false;

    // Iterate through all the outputs constructing the final balances of every group.
    for (const auto &outp : tx.vout)
    {
        const CScript &scriptPubKey = outp.scriptPubKey;
        CTokenGroupInfo tokenGrp(scriptPubKey);
        if (tokenGrp.invalid)
            return state.Invalid(false, REJECT_INVALID, "bad OP_GROUP");
        if (tokenGrp.associatedGroup != NoGroup)
        {
            gBalance[tokenGrp.associatedGroup].numOutputs += 1;

            if (tokenGrp.quantity > 0)
            {
                if (std::numeric_limits<CAmount>::max() - gBalance[tokenGrp.associatedGroup].output < tokenGrp.quantity)
                    return state.Invalid(false, REJECT_INVALID, "token overflow");
                gBalance[tokenGrp.associatedGroup].output += tokenGrp.quantity;
                anyOutputGroups = true;
            }
            else if (tokenGrp.quantity == 0)
            {
                return state.Invalid(false, REJECT_INVALID, "OP_GROUP quantity is zero");
            }
            else // this is an authority output
            {
                gBalance[tokenGrp.associatedGroup].ctrlOutputPerms |= (GroupAuthorityFlags)tokenGrp.quantity;
                anyOutputControlGroups = true;
            }
        }
    }

    // Now iterate through the inputs applying them to match outputs.
    // If any input utxo address matches a non-bitcoin group address, defer since this could be a mint or burn
    for (const auto &inp : tx.vin)
    {
        const COutPoint &prevout = inp.prevout;
        const Coin &coin = view.AccessCoin(prevout);
        if (coin.IsSpent()) // should never happen because you've already CheckInputs(tx,...)
        {
            LogPrint("tokens", "%s - Checking token group for spent coin", __func__);
            return state.Invalid(false, REJECT_INVALID, "already-spent");
        }
        // no prior coins can be grouped.
        if (coin.nHeight < Params().OpGroup_StartHeight())
            continue;
        const CScript &script = coin.out.scriptPubKey;
        CTokenGroupInfo tokenGrp(script);
        // The prevout should never be invalid because that would mean that this node accepted a block with an
        // invalid OP_GROUP tx in it.
        if (tokenGrp.invalid)
            continue;
        CAmount amount = tokenGrp.quantity;
        if (tokenGrp.controllingGroupFlags != GroupAuthorityFlags::NONE)
        {
            auto temp = tokenGrp.controllingGroupFlags;
            // outputs can have all the permissions of inputs, except for 1 special case
            // If CCHILD is not set, no outputs can be authorities (so unset the CTRL flag)
            if (hasCapability(temp, GroupAuthorityFlags::CCHILD))
            {
                gBalance[tokenGrp.associatedGroup].allowedCtrlOutputPerms |= temp;
            }
            // Track what permissions this transaction has
            gBalance[tokenGrp.associatedGroup].ctrlPerms |= temp;
        }
        if (tokenGrp.associatedGroup != NoGroup)
        {
            if (amount < 0)
            {
                // from the perspective of balancing, a controller utxo is empty so nothing to add here
            }
            else
            {
                if (std::numeric_limits<CAmount>::max() - gBalance[tokenGrp.associatedGroup].input < amount)
                    return state.Invalid(false, REJECT_INVALID, "token overflow");
                gBalance[tokenGrp.associatedGroup].input += amount;
            }
        }
    }

    // Now pass thru the outputs ensuring balance or mint/melt permission
    for (auto &txo : gBalance)
    {
        CBalance &bal = txo.second;
        // If it has an authority, with no input authority, check mint
        if (hasCapability(bal.ctrlOutputPerms, GroupAuthorityFlags::CTRL) &&
            (bal.ctrlPerms == GroupAuthorityFlags::NONE))
        {
            CHashWriter mintGrp(SER_GETHASH, PROTOCOL_VERSION);
            mintGrp << tx.vin[0].prevout
                    << (((uint64_t)bal.ctrlOutputPerms) & ~((uint64_t)GroupAuthorityFlags::ALL_BITS));
            CTokenGroupID newGrpId(mintGrp.GetHash());

            if (newGrpId == txo.first) // This IS new group because id matches hash, so allow all authority.
            {
                if (bal.numOutputs != 1) // only allow the single authority tx during a create
                    return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-create",
                         "Multiple grouped outputs created during group creation transaction");
                bal.allowedCtrlOutputPerms = bal.ctrlPerms = GroupAuthorityFlags::ALL;
            }
        }

        if ((bal.input > bal.output) && !hasCapability(bal.ctrlPerms, GroupAuthorityFlags::MELT))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-melt",
                "Group input exceeds output, but no melt permission");
        }
        if ((bal.input < bal.output) && !hasCapability(bal.ctrlPerms, GroupAuthorityFlags::MINT))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-mint",
                "Group output exceeds input, but no mint permission");
        }
        // Some output permissions are set that are not in the inputs
        if (((uint64_t)(bal.ctrlOutputPerms & GroupAuthorityFlags::ALL)) &
            ~((uint64_t)(bal.allowedCtrlOutputPerms & GroupAuthorityFlags::ALL)))
        {
                return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-perm",
                "Group output permissions exceeds input permissions");
        }
    }

    return true;
}


bool CTokenGroupID::isUserGroup(void) const { return (!data.empty()); }