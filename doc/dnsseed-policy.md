# Expectations for DNS Seed operators

Table of Contents
------------------
- [Expectations for DNS Seed operators](#expectations-for-dns-seed-operators)
        - [1. A DNS seed operating organization or person is expected](#1-a-dns-seed-operating-organization-or-person-is-expected)
        - [2. The DNS seed results must consist exclusively of fairly selected and](#2-the-dns-seed-results-must-consist-exclusively-of-fairly-selected-and)
        - [3. For the avoidance of doubt, the results may be randomized but must not](#3-for-the-avoidance-of-doubt-the-results-may-be-randomized-but-must-not)
        - [4. The results may not be served with a DNS TTL of less than one minute.](#4-the-results-may-not-be-served-with-a-dns-ttl-of-less-than-one-minute)
        - [5. Any logging of DNS queries should be only that which is necessary](#5-any-logging-of-dns-queries-should-be-only-that-which-is-necessary)
        - [6. Information gathered as a result of the operators node-spidering](#6-information-gathered-as-a-result-of-the-operators-node-spidering)
        - [7. Operators are encouraged, but not required, to publicly document the](#7-operators-are-encouraged-but-not-required-to-publicly-document-the)
        - [8. A reachable email contact address must be published for inquiries](#8-a-reachable-email-contact-address-must-be-published-for-inquiries)
    - [See also](#see-also)

Ion Core attempts to minimize the level of trust in DNS seeds,
but DNS seeds still pose a small amount of risk for the network.
As such, DNS seeds must be run by entities which have some minimum
level of trust within the ION community.

Other implementations of ION software may also use the same
seeds and may be more exposed. In light of this exposure, this
document establishes some basic expectations for operating dnsseeds.

### 1. A DNS seed operating organization or person is expected to follow good
host security practices, maintain control of applicable infrastructure,
and not sell or transfer control of the DNS seed. Any hosting services
contracted by the operator are equally expected to uphold these expectations.

### 2. The DNS seed results must consist exclusively of fairly selected and
functioning ION nodes from the public network to the best of the
operators understanding and capability.

### 3. For the avoidance of doubt, the results may be randomized but must not
single-out any group of hosts to receive different results unless due to an
urgent technical necessity and disclosed.

### 4. The results may not be served with a DNS TTL of less than one minute.

### 5. Any logging of DNS queries should be only that which is necessary
for the operation of the service or urgent health of the ION
network and must not be retained longer than necessary nor disclosed
to any third party.

### 6. Information gathered as a result of the operators node-spidering
(not from DNS queries) may be freely published or retained, but only
if this data was not made more complete by biasing node connectivity
(a violation of expectation (1)).

### 7. Operators are encouraged, but not required, to publicly document the
details of their operating practices.

### 8. A reachable email contact address must be published for inquiries
related to the DNS seed operation.

If these expectations cannot be satisfied the operator should
discontinue providing services and contact the active ION
Core development team as well as posting on the
[ION Forum](https://forum.ioncoin.org).

Behavior outside of these expectations may be reasonable in some
situations but should be discussed in public in advance.

## See also
- [bitcoin-seeder](https://github.com/sipa/bitcoin-seeder) is a reference implementation of a DNS seed.
