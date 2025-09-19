# eip712sign

Small golang utility used to sign EIP-712 typed data or hashes, and EIP-191 personal messages. Supports:

- ledgers
- trezors
- mnemonics
- raw private keys

<!-- Badge row 1 - status -->

[![GitHub contributors](https://img.shields.io/github/contributors/base/eip712sign)](https://github.com/base/eip712sign/graphs/contributors)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/base/eip712sign)](https://github.com/base/eip712sign/graphs/contributors)
[![GitHub Stars](https://img.shields.io/github/stars/base/eip712sign.svg)](https://github.com/base/eip712sign/stargazers)
![GitHub repo size](https://img.shields.io/github/repo-size/base/eip712sign)
[![GitHub](https://img.shields.io/github/license/base/eip712sign?color=blue)](https://github.com/base/eip712sign/blob/main/LICENSE)

<!-- Badge row 2 - links and profiles -->

[![Website base.org](https://img.shields.io/website-up-down-green-red/https/base.org.svg)](https://base.org)
[![Blog](https://img.shields.io/badge/blog-up-green)](https://base.mirror.xyz/)
[![Docs](https://img.shields.io/badge/docs-up-green)](https://docs.base.org/)
[![Discord](https://img.shields.io/discord/1067165013397213286?label=discord)](https://base.org/discord)
[![Twitter BuildOnBase](https://img.shields.io/twitter/follow/BuildOnBase?style=social)](https://twitter.com/BuildOnBase)

<!-- Badge row 3 - detailed status -->

[![GitHub pull requests by-label](https://img.shields.io/github/issues-pr-raw/base/eip712sign)](https://github.com/base/eip712sign/pulls)
[![GitHub Issues](https://img.shields.io/github/issues-raw/base/eip712sign.svg)](https://github.com/base/eip712sign/issues)

### Installation

```shell
go install github.com/base/eip712sign
```

### Flags

```shell
Usage of eip712sign:
  -address
    	Print address of signer and exit
  -data string
    	Data to be signed
  -hd-paths string
    	Hierarchical deterministic derivation path for mnemonic, ledger, or trezor (default "m/44'/60'/0'/0/0")
  -index int
    	Device index to use (if multiple devices are connected)
  -ledger
    	Use ledger device for signing
  -mnemonic string
    	Mnemonic to use for signing
  -prefix string
    	String that prefixes the data to be signed (default "vvvvvvvv")
  -private-key string
    	Private key to use for signing
  -skip-sender
    	Skip adding the --sender flag to forge script commands
  -suffix string
    	String that suffixes the data to be signed (default "^^^^^^^^")
  -text
    	Use EIP-191 message format for signing (default is EIP-712)
  -trezor
    	Use trezor device for signing
  -workdir string
    	Directory in which to run the subprocess (default ".")
```

### Usage

`eip712sign` can either be run as a command wrapper, or data can be piped in via stdin.
The former is recommended as it will only attempt to sign if the subprocess exit code is 0.

```shell
eip712sign --ledger -- <COMMAND>
```

or

```shell
<COMMAND> | eip712sign --ledger
```

Example signing some bytes output from a forge script:

```shell
eip712sign --ledger -- forge script --rpc-url <RPC_URL> SomeScript
```

`eip712sign` will parse the stdout from the subprocess, and by default, sign any hex string between the magic strings `vvvvvvvv` and `^^^^^^^^`.
This prefix + suffix can be configured using the `-prefix` and `-suffix` flags.
In this example, `SomeScript` should print this to the console, for example:

```solidity
function printDataToSign(bytes memory data) internal pure {
    console.log("vvvvvvvv");
    console.logBytes(data);
    console.log("^^^^^^^^");
}
```

...where `data` is 66 bytes in length for EIP-712 hashes, or JSON for EIP-712 typed data (can optionally be hex encoded).

Example output:

```shell
Compiling 5 files with 0.8.15
Solc 0.8.15 finished in 7.01s
Compiler run successful!
Script ran successfully.

== Logs ==
  vvvvvvvv
  0x19011b6ca1022dcb8ee88e2ab8dd1adf6f6bfa6af586f8b074e99c952e6e3c6befadd5c5183a56f8aa2520c9522029fc20aba61ce6c6aa32aec3b00519c95eb819e8
  ^^^^^^^^

forge exited with code 0

Domain hash: 0x1b6ca1022dcb8ee88e2ab8dd1adf6f6bfa6af586f8b074e99c952e6e3c6befad
Message hash: 0xd5c5183a56f8aa2520c9522029fc20aba61ce6c6aa32aec3b00519c95eb819e8

Data: 0x19011b6ca1022dcb8ee88e2ab8dd1adf6f6bfa6af586f8b074e99c952e6e3c6befadd5c5183a56f8aa2520c9522029fc20aba61ce6c6aa32aec3b00519c95eb819e8
Signer: 0x4A02DE0C8a1C74AB99D1eCeb56d1d5f54B8293b0
Signature: 36b6a15e3e86b1ae44bdfc9183c4d86b0eaead44c838530ecb2e43dd0618559579195d42fe63868a44ee0279feef0181b1a9ed3b0faa89bf1ebd48b0f48f54bc1c
```
