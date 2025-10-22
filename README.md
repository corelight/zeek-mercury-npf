# Mercury NPF for Zeek

This Zeek plugin implements the [Network Protocol Fingerprinting (NPF) format](https://github.com/cisco/mercury/blob/main/doc/npf.md) as specified in the [Mercury](https://github.com/cisco/mercury) project.

## Overview

The plugin inspects the following protocols and generates the NPF for them:

* TCP
* TLS and DTLS
* QUIC
* HTTP
* SSH
* OpenVPN (requires installation of https://github.com/corelight/zeek-spicy-openvpn)
* STUN (requires installation of https://github.com/corelight/zeek-spicy-stun)

## Installation

This plugin is distributed as a Zeek package. You can install it using the Zeek package manager `zkg` after cloning the repository using

```bash
zkg install .
```

### Configuration

The plugin provides configuration options to control the version of the fingerprints generated for some protocols.

#### QUIC

You can choose between two QUIC fingerprint versions:

*   `Mercury::QUIC::MERCURY_QUIC` (default)
*   `Mercury::QUIC::MERCURY_QUIC_1`

To change the version, add the following to your `local.zeek`:

```zeek
redef Mercury::QUIC::fingerprint_version = Mercury::QUIC::MERCURY_QUIC_1
```

#### TLS/DTLS

You can choose between three TLS/DTLS fingerprint versions:

*   `Mercury::TLS::MERCURY_TLS` (default)
*   `Mercury::TLS::MERCURY_TLS_1`
*   `Mercury::TLS::MERCURY_TLS_2`

To change the version, add the following to your `local.zeek`:

```zeek
redef Mercury::TLS::fingerprint_version = Mercury::TLS::MERCURY_TLS_2;
```
