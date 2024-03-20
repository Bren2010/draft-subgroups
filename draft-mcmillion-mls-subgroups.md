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
: A (normally) human operator of a device. Users may have many devices, but a
  device only belongs to one user.

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
subgroup_secret_tree_root
    = MLS-Exporter("Subgroup Secret Tree", "", KDF.Nh)
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
the subgroup `leaf_index`, chooses a 32-bit number `random`, converts both to a
series of bits, and concatenates them to get a series of 64 bits: `leaf_index ||
random`. This series of bits is used to lookup a node in the Secret Tree,
`tree_node_secret`.

For a KeyPackage `init_key`, the device computes:

~~~
init_secret = DeriveSecret(tree_node_secret, "Subgroup KeyPackage")
init_priv, init_pub = KEM.DeriveKeyPair(init_secret)
~~~

For a LeafNode `encryption_key`, the device computes:

~~~
leaf_secret = DeriveSecret(tree_node_secret, "Subgroup LeafNode")

leaf_node_secret = DeriveSecret(leaf_secret, "node")
leaf_priv, leaf_pub = KEM.DeriveKeyPair(leaf_node_secret)
~~~

If the LeafNode is part of a Commit message, the device also computes
`path_secret[0]` from `leaf_secret`:

~~~
path_secret[0] = DeriveSecret(leaf_secret, "path")
~~~

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

If two devices encrypt a message with the same key simultaneously, they may
have already deleted the relevant encryption key by the time they receive the
other device's message, which will cause a decryption failure. This is a
functional issue, and the best solution depends on whether the Delivery Service
is strongly or eventually consistent {{?I-D.ietf-mls-architecture}}. Devices
communicating with a strongly consistent DS can prevent this issue by checking
that they have processed all the messages sent to a group before sending their
own message. Alternatively, devices communicating with an eventually consistent
DS may simply need to retain encryption keys for a short period of time after
use in case they are still necessary.

However, if two devices encrypt a message with both the same key and nonce
simultaneously, this could compromise the message's confidentiality and
integrity. Devices prevent this by ensuring two devices in a subgroup never
choose the same `reuse_guard`.

## Small-Space PRP

A small-space pseudorandom permutation (PRP) is a cryptographic algorithm that
works similar to a block cipher, while also being able to adhere to format
constraints. In particular, it is able to perform a psuedorandom permutation
over an arbitrary input and output space.

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

`prp_key` is computed in a way that it is unique to the key-nonce pair and
computable by all the devices in a subgroup (but nobody else). `reuse_guard` is
computed in a way that it appears random to outside observers (in particular, it
does not leak which device sent the message), but two devices will never
generate the same value.

# Adding New Devices

When a user adds a new authorized device to their account, there are several
pieces of cryptographic state that need to be synchronized before the device can
start sending and receiving messages. The device can either get this state from
another one of the user's devices, or if all of the user's other devices are
offline, the device can use a series of external joins to prepare itself.

## Synchronizing from Another Device

If the new device is being added by another online device, this device sends a
Welcome message to the new device, adding the new device to the subgroup, that
contains a `new_device_state` extension in the GroupInfo:

~~~
opaque MLSState<V>;

enum {
  reserved(0),
  empty(1),
  present(2),
} SecretTreeNodeType;

struct {
  SecretTreeNodeType node_type;
  select(SecretTreeNode.node_type) {
    case empty:
      SecretTreeNode left;
      SecretTreeNode right;
    case present:
      opaque value<V>;
  }
} SecretTreeNode;

struct {
  uint64 epoch;
  SecretTreeNode root;
} EpochSecretTree;

struct {
  KeyPackageRef ref;
  opaque init_secret<V>;
  opaque leaf_secret<V>;
} KeyPackageKey;

struct {
  opaque signature_private_key<V>;
  opaque subgroup_extension_key<V>;
  EpochSecretTree secret_trees<V>;
  KeyPackageKey key_package_keys<V>;
  MLSState group_states<V>;
} NewDeviceState;
~~~

The `signature_private_key` contains the serialized signature private key of the
virtual client. Every device and virtual client SHOULD have distinct signature
keys. The `subgroup_extension_key` is the encryption key for the subgroup
extension ({{subgroup-extension}}). The `secret_trees` array contains the
serialized Secret Trees for any epochs where they may still be necessary. The
`key_package_keys` array contains the `init_secret` and `leaf_secret` for any
KeyPackages that are still unused but have been purged from the Secret Tree. And
finally, the `group_states` array contains the cryptographic states of all the
groups that the virtual client is a member of, serialized in an
application-specific way.

## Joining Externally

Without another online device to bootstrap from, the new device can follow these
steps to join externally:

1. Issue a credential for the virtual client with a new signature key and
   generate a new subgroup extension key.
2. Perform an External Join to the subgroup. Send an application message
   containing a `ResyncMessage` to the subgroup with the new keys.
3. Replace all unused KeyPackages with new KeyPackages, generated from the new
   subgroup epoch.
4. Perform an External Join to all of the groups that the virtual client is a
   member of, using LeafNodes generated from the new subgroup epoch. Welcome
   messages which were unprocessed by the offline devices are discarded, and
   these groups are Externally Joined instead (potentially being queued for user
   approval first).

~~~
struct {
  opaque signature_private_key<V>;
  opaque subgroup_extension_key<V>;
} ResyncMessage;
~~~

Note that this involves changing the subgroup extension key. Devices that were
in the subgroup before the new device joined externally can determine whether to
use the new or old subgroup extension key by checking whether the new or old
credential is in the relevant LeafNode.

Also note that the new device learns the set of groups that the virtual client
is a member of, including groups corresponding to unprocessed Welcome messages,
from the Delivery Service, which has access to this information as part of
supporting External Joins.

# Aligning Security of Groups

Subgroups deprive supergroup members of visibility into whether key rotation is
happening on a regular basis, and the extent to which compromised devices may
have access to group secrets. As such, subgroups need to enforce policies that
manage this concern.

A subgroup MUST have either the same or a stronger policy on how frequently
devices must update their leaf node, than the groups that the virtual client is
a member of.

Any time that a device is removed from a subgroup, an Update (or Commit with
`path` populated) MUST be sent to all groups that the virtual client is a member
of.

# Security Considerations

TODO Security


# IANA Considerations

This document defines two new MLS Extension Types, and a new MLS Exporter Label.

## MLS Extension Types

| Value            | Name                     | Message(s) | R | Ref      |
|:-----------------|:-------------------------|:-----------|:--|:---------|
| 0x0006           | subgroup                 | LN, KP     | - | RFC XXXX |
| 0x0007           | new_device_state         | GI         | - | RFC XXXX |

## MLS Exporter Labels

| Label                  | Recommended | Reference |
|:-----------------------|:------------|:----------|
| "Subgroup Secret Tree" | -           | RFC XXXX  |

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
