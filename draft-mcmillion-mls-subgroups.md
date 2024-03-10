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


# Secret Tree

The Subgroups protocol uses a Secret Tree similar to {{RFC9420}}. The root of
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
`subgroup_secret_tree_root`, is the value associated with the empty bit string
"". The left child is the value associated with the bit string "0", while the
right child is the value associated with the bit string "1", and so on
recursively.

# Small-Space PRP

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
