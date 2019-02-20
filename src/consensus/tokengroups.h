// Copyright (c) 2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUPS_H
#define TOKEN_GROUPS_H

#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "pubkey.h"
//#include "script/standard.h"
#include <unordered_map>
class CWallet;

/** Transaction cannot be committed on my fork */
static const unsigned int REJECT_GROUP_IMBALANCE = 0x104;

enum class TokenGroupIdFlags : uint8_t
{
    NONE = 0,
    SAME_SCRIPT = 1U, // covenants/ encumberances -- output script template must match input
    BALANCE_BCH = 1U << 1, // group inputs and outputs must balance both tokens and BCH
    STICKY_MELT = 1U << 2, // group can always melt tokens
    MGT_TOKEN = 1U << 3, // group does not pay fees in XDM

    DEFAULT = 0
};

inline TokenGroupIdFlags operator|(const TokenGroupIdFlags a, const TokenGroupIdFlags b)
{
    TokenGroupIdFlags ret = (TokenGroupIdFlags)(((uint8_t)a) | ((uint8_t)b));
    return ret;
}

inline TokenGroupIdFlags operator~(const TokenGroupIdFlags a)
{
    TokenGroupIdFlags ret = (TokenGroupIdFlags)(~((uint8_t)a));
    return ret;
}

inline TokenGroupIdFlags operator&(const TokenGroupIdFlags a, const TokenGroupIdFlags b)
{
    TokenGroupIdFlags ret = (TokenGroupIdFlags)(((uint8_t)a) & ((uint8_t)b));
    return ret;
}

inline TokenGroupIdFlags &operator|=(TokenGroupIdFlags &a, const TokenGroupIdFlags b)
{
    a = (TokenGroupIdFlags)(((uint8_t)a) | ((uint8_t)b));
    return a;
}

inline TokenGroupIdFlags &operator&=(TokenGroupIdFlags &a, const TokenGroupIdFlags b)
{
    a = (TokenGroupIdFlags)(((uint8_t)a) & ((uint8_t)b));
    return a;
}
inline bool hasTokenGroupIdFlag(TokenGroupIdFlags object, TokenGroupIdFlags flag) {
    return (((uint8_t)object) & ((uint8_t)flag)) == (uint8_t)flag;
}

// The definitions below are used internally.  They are defined here for use in unit tests.
class CTokenGroupID
{
protected:
    std::vector<unsigned char> data;
    enum
    {
        PARENT_GROUP_ID_SIZE = 32
    };

public:
    //* no token group, which is distinct from the bitcoin token group
    CTokenGroupID() {}
    //* for special token groups, of which there is currently only the bitcoin token group (0)
    CTokenGroupID(unsigned char c) : data(PARENT_GROUP_ID_SIZE) { data[0] = c; }
    //* handles CKeyID and CScriptID
    CTokenGroupID(const uint160 &id) : data(ToByteVector(id)) {}
    //* handles single mint group id, and possibly future larger size CScriptID
    CTokenGroupID(const uint256 &id) : data(ToByteVector(id)) {}
    //* Assign the groupID from a vector
    CTokenGroupID(const std::vector<unsigned char> &id) : data(id)
    {
        // for the conceivable future there is no possible way a group could be bigger but the spec does allow larger
        if (!(id.size() < OP_PUSHDATA1)) {
            LogPrint("tokens", "%s - Debug Assertion failed", __func__);
        };
    }

    void NoGroup(void) { data.resize(0); }
    bool operator==(const CTokenGroupID &id) const { return data == id.data; }
    bool operator!=(const CTokenGroupID &id) const { return data != id.data; }
    //* returns true if this is a user-defined group -- ie NOT bitcoin cash or no group
    bool isUserGroup(void) const;
    //* returns true if this is a subgroup
    bool isSubgroup(void) const;
    //* returns the parent group if this is a subgroup or itself.
    CTokenGroupID parentGroup(void) const;

    const std::vector<unsigned char> &bytes(void) const { return data; }
    //* Convert this token group ID into a mint/melt address
    // CTxDestination ControllingAddress(txnouttype addrType) const;
    //* Returns this groupID as a string in bech32 format
    // std::string Encode(const CChainParams &params = Params()) const;

    bool hasFlag(TokenGroupIdFlags flag) const;
};

namespace std
{
template <>
struct hash<CTokenGroupID>
{
public:
    size_t operator()(const CTokenGroupID &s) const
    {
        const std::vector<unsigned char> &v = s.bytes();
        int sz = v.size();
        if (sz >= 4)
            return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) << v[3];
        else if (sz > 0)
            return v[0]; // It would be better to return all bytes but sizes 1 to 3 currently unused
        else
            return 0;
    }
};
}

enum class GroupAuthorityFlags : uint64_t
{
    CTRL = 1ULL << 63, // Is this a controller utxo (forces negative number in amount)
    MINT = 1ULL << 62, // Can mint tokens
    MELT = 1ULL << 61, // Can melt tokens,
    CCHILD = 1ULL << 60, // Can create controller outputs
    RESCRIPT = 1ULL << 59, // Can change the redeem script
    SUBGROUP = 1ULL << 58,

    NONE = 0,
    ALL = CTRL | MINT | MELT | CCHILD | RESCRIPT | SUBGROUP,
    ALL_BITS = 0xffffULL << (64 - 16)
};

inline GroupAuthorityFlags operator|(const GroupAuthorityFlags a, const GroupAuthorityFlags b)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(((uint64_t)a) | ((uint64_t)b));
    return ret;
}

inline GroupAuthorityFlags operator~(const GroupAuthorityFlags a)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(~((uint64_t)a));
    return ret;
}

inline GroupAuthorityFlags operator&(const GroupAuthorityFlags a, const GroupAuthorityFlags b)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(((uint64_t)a) & ((uint64_t)b));
    return ret;
}

inline GroupAuthorityFlags &operator|=(GroupAuthorityFlags &a, const GroupAuthorityFlags b)
{
    a = (GroupAuthorityFlags)(((uint64_t)a) | ((uint64_t)b));
    return a;
}

inline GroupAuthorityFlags &operator&=(GroupAuthorityFlags &a, const GroupAuthorityFlags b)
{
    a = (GroupAuthorityFlags)(((uint64_t)a) & ((uint64_t)b));
    return a;
}

inline bool hasCapability(GroupAuthorityFlags object, const GroupAuthorityFlags capability)
{
    return (((uint64_t)object) & ((uint64_t)capability)) != 0;
}

inline CAmount toAmount(GroupAuthorityFlags f) { return (CAmount)f; }
class CTokenGroupInfo
{
public:
    CTokenGroupInfo() : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(true)
    {
    }
    CTokenGroupInfo(const CTokenGroupID &associated, const GroupAuthorityFlags controllingGroupFlags, CAmount qty = 0)
        : associatedGroup(associated), controllingGroupFlags(controllingGroupFlags), quantity(qty), invalid(false)
    {
    }
    CTokenGroupInfo(const CKeyID &associated, const GroupAuthorityFlags controllingGroupFlags, CAmount qty = 0)
        : associatedGroup(associated), controllingGroupFlags(controllingGroupFlags), quantity(qty), invalid(false)
    {
    }
    // Return the controlling (can mint and burn) and associated (OP_GROUP in script) group of a script
    CTokenGroupInfo(const CScript &script);

    CTokenGroupID associatedGroup; // The group announced by the script (or the bitcoin group if no OP_GROUP)
    GroupAuthorityFlags controllingGroupFlags; // if the utxo is a controller this is not NONE
    CAmount quantity; // The number of tokens specified in this script
    bool invalid;

    // return true if this object is a token authority.
    bool isAuthority() const
    {
        return ((controllingGroupFlags & GroupAuthorityFlags::CTRL) == GroupAuthorityFlags::CTRL);
    }
    // return true if this object is a new token creation output.
    // Note that the group creation nonce cannot be 0
    bool isGroupCreation(TokenGroupIdFlags tokenGroupIdFlags = TokenGroupIdFlags::NONE) const
    {
        bool hasNonce = ((uint64_t)quantity & (uint64_t)~GroupAuthorityFlags::ALL_BITS) != 0;

        return (((controllingGroupFlags & GroupAuthorityFlags::CTRL) == GroupAuthorityFlags::CTRL) && hasNonce && associatedGroup.hasFlag(tokenGroupIdFlags));
    }
    // return true if this object allows minting.
    bool allowsMint() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT)) ==
               (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MINT);
    }
    // return true if this object allows melting.
    bool allowsMelt() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MELT)) ==
               (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::MELT);
    }
    // return true if this object allows child controllers.
    bool allowsRenew() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::CCHILD)) ==
               (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::CCHILD);
    }
    // return true if this object allows rescripting.
    bool allowsRescript() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::RESCRIPT)) ==
               (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::RESCRIPT);
    }
    // return true if this object allows subgroups.
    bool allowsSubgroup() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::SUBGROUP)) ==
               (GroupAuthorityFlags::CTRL | GroupAuthorityFlags::SUBGROUP);
    }

    bool isInvalid() const { return invalid; };
    bool operator==(const CTokenGroupInfo &g)
    {
        if (g.invalid || invalid)
            return false;
        return ((associatedGroup == g.associatedGroup) && (controllingGroupFlags == g.controllingGroupFlags));
    }
};

// Verify that the token groups in this transaction properly balance
bool CheckTokenGroups(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &view);

// Return true if any output in this transaction is part of a group
bool IsAnyTxOutputGrouped(const CTransaction &tx);

bool IsAnyTxOutputGroupedCreation(const CTransaction &tx, const TokenGroupIdFlags tokenGroupIdFlags = TokenGroupIdFlags::NONE);

// Serialize a CAmount into an array of bytes.
// This serialization does not store the length of the serialized data within the serialized data.
// It is therefore useful only within a system that already identifies the length of this field (such as a CScript).
std::vector<unsigned char> SerializeAmount(CAmount num);

// Deserialize a CAmount from an array of bytes.
// This function uses the size of the vector to determine how many bytes were used in serialization.
// It is therefore useful only within a system that already identifies the length of this field (such as a CScript).
CAmount DeserializeAmount(std::vector<unsigned char> &vec);

// Convenience function to just extract the group from a script
inline CTokenGroupID GetTokenGroup(const CScript &script) { return CTokenGroupInfo(script).associatedGroup; }
extern CTokenGroupID NoGroup;

#endif