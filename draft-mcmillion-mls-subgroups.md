---
title: "MLS Subgroups"
category: info

docname: draft-mcmillion-mls-subgroups-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "Bren2010/draft-subgroups"
  latest: "https://Bren2010.github.io/draft-subgroups/draft-mcmillion-mls-subgroups.html"

author:
 -
    fullname: "Brendan McMillion"
    email: "brendanmcmillion@gmail.com"

normative:
  NIST:
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
    title: "Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption"
    author:
      - name: Morris Dworkin

informative:


--- abstract

This document describes how the user of an MLS-based messaging service can
synchronize the operation of its devices, such that they behave as a single
virtual MLS client. This prevents other users of the messaging service from
being able to tell when a user changes its set of authorized devices, or which
device the user sent a message from.

--- middle

# Introduction

MLS allows users to communicate in an end-to-end encrypted fashion but doesn't
describe how to synchronize the operation of a user's devices. Instead,
applications are generally expected to create distinct MLS clients for each
device that a user has, and to ensure that all of the user's devices are added or
removed from a group atomically. This creates some technical difficulties, as it
can be hard for other members to ensure that the group truly stays in-sync with
each user's set of authorized devices. It also creates a privacy issue because
the members of a group can see which device a user sent a given message from, or
when any user changes its set of authorized devices.

This document describes how to use an MLS group between all of a user's
authorized devices to synchronize behavior, such that other users of the
messaging service only see the user as a single MLS client. It does this in a
way that preserves the Forward Secrecy and Post-Compromise Security guarantees
of the groups that the user participates in, without requiring changes to the
wire format of MLS.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Device:
: A user interface for messaging, performing encryption as needed.

User:
: A (normally) human operator of a device.

Subgroup:
: An MLS group whose membership is exactly the set of authorized devices of a single user.

Virtual Client:
: An MLS client that is controlled by one of many devices and synchronized by a subgroup.

Supergroup:
: Refers to any MLS group which is not a subgroup.

# Generation of Private Keys

When devices generate new asymmetric keypairs for a virtual client (such as a
KeyPackage `init_key` or LeafNode `encryption_key`), they must do so in a way
that the other devices participating in the subgroup can compute the private key
as well. In the Subgroups protocol, a virtual client's private keys are derived
deterministically from a secret exported from the most recent epoch in a
subgroup. An extension is added to KeyPackages and LeafNodes generated this way
to communicate to the other devices, which may not become aware of the keypair
for several epochs, the epoch the private key was generated from.

Note that signature private keys are not generated this way. A virtual client's
signature private key is generated once and shared directly with new devices.

## Secret Tree

The Subgroups protocol uses a Secret Tree similar to {{!RFC9420}}. The root of
the Secret Tree is an exported secret from a given epoch of a subgroup:

~~~
subgroup_secret_tree_root = MLS-Exporter("Subgroup Secret Tree", "", KDF.Nh)
~~~

The left and right child of a node in the Secret Tree are computed as follows:

~~~ aasvg
tree_node_[N]_secret
        |
        |
        +--> ExpandWithLabel(., "tree", "left", KDF.Nh)
        |    = tree_node_[left(N)]_secret
        |
        +--> ExpandWithLabel(., "tree", "right", KDF.Nh)
             = tree_node_[right(N)]_secret
~~~

The Secret Tree maps bit strings to a value of size `KDF.Nh`. The root,
`subgroup_secret_tree_root`, is the value associated with the empty bit string.
Its left child is the value associated with the bit string "0", while its right
child is the value associated with the bit string "1", and so on recursively.

Devices follow a strict deletion schedule, and delete any node as soon as:

- its left and right children have been computed, or
- a private key has been derived from the node.

This ensures that any private keys that are derived from the Secret Tree can be
deleted and won't be able to be re-derived, providing Forward Secrecy.

## Private Keys

Devices will need to generate either an `init_key` for a KeyPackage, or an
`encryption_key` for a LeafNode. To do this, the device finds its leaf index in
the subgroup `leaf_index`, chooses a random 32-bit number `random`, converts
both to a series of bits, and concatenates them to get a series of 64 bits:
`leaf_index || random`. This series of bits is used to lookup a node in the
Secret Tree, `tree_node_secret`.

For a KeyPackage `init_key`, the device computes:

~~~
init_secret = DeriveSecret(tree_node_secret, "Subgroup KeyPackage")
init_priv, init_pub = KEM.DeriveKeyPair(init_secret)
~~~

For a LeafNode `encryption_key`, the device computes:

~~~
leaf_secret = DeriveSecret(tree_node_secret, "Subgroup LeafNode")
~~~

`leaf_node_secret` and `leaf_priv` are then derived from `leaf_secret` according
to {{!RFC9420}}.

Individual devices MUST take care to avoid reusing `random` values. Note that
the Secret Tree nodes are computed with the subgroup ciphersuite's algorithms,
but `init_secret` and `leaf_secret` are computed with the supergroup
ciphersuite's algorithms.

## Subgroup Extension

As mentioned, devices may not always be immediately aware of when another device
has generated a private key. This means that devices need a way to communicate
to each other the information they used to derive a private key. The `subgroup`
extension in a KeyPackage or LeafNode provides this information:

~~~
struct {
  uint64 epoch;
  uint32 leaf_index;
  uint32 random;
} PrivateKeyInfo;

opaque subgroup<V>;
~~~

The extension is a byte string containing a `PrivateKeyInfo` struct, which has
been encrypted with the AEAD from the subgroup's ciphersuite:

~~~
nonce is sampled at random
subgroup = nonce || AEAD.Seal(key, nonce, "", PrivateKeyInfo)
~~~

The `epoch` field is the epoch of the subgroup that was used, `leaf_index` is
the index of the device's leaf in the subgroup, and `random` is the random value
chosen by the device during generation.

The `key` used for encryption is fixed long-term and shared among the devices in
a subgroup.

# Application Messages

Given that MLS generates the encryption keys and nonces for application and
handshake messages sequentially, but a virtual client may send messages from
several devices simultaneously, devices must take care to avoid reusing
encryption keys and nonces.

If two devices encrypt a message with the same key simultaneously, they will
have already deleted the encryption key by the time they receive the other's
message, which will cause a decryption failure. This is a functional issue that
devices can coordinate with the Delivery Service to prevent.

If two devices encrypt a message with the same key and nonce simultaneously,
this could compromise the message's confidentiality and integrity. Devices
prevent this by ensuring two devices in a subgroup never choose the same
`reuse_guard`.

## Small-Space PRP

A small-space pseudorandom permutation (PRP) is a cryptographic algorithm that
works similar to a block cipher, while also being able to adhere to format
constraints. In particular, it is able to create perform a psuedorandom
permutation over an arbitrary input and output space.

This document uses the FF1 mode from {{NIST}} with the input-output space of
32-bit integers, instantiated with AES-128.

~~~
output = SmallSpacePRP.Encrypt(key, input)
input = SmallSpacePRP.Decrypt(key, output)
~~~

## Reuse Guard

In the unmodified MLS protocol, the `reuse_guard` is chosen randomly. In the
Subgroups protocol, devices choose a random value `x` such that `x` modulo the
number of leaves in the subgroup is equal to its `leaf_index`. They then
calculate:

~~~
prp_key = ExpandWithLabel(key_schedule_nonce, "reuse guard", leaf_secret, 16)
reuse_guard = SmallSpacePRP.Encrypt(prp_key, x)
~~~

ExpandWithLabel is computed with the subgroup ciphersuite's algorithms.
`key_schedule_nonce` is the nonce provided by the key schedule for encrypting
this message, and `leaf_secret` is the secret corresponding to the virtual
client's LeafNode in the supergroup.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.

- Label "Subgroup Secret Tree", "Subgroup KeyPackage", "Subgroup LeafNode"
- Extension "subgroup"

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
