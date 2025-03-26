package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// TestEIP712Implementation verifies our implementation against the test case
// from the Python eth-account library maintained by the Ethereum Foundation.
// Source: https://github.com/ethereum/eth-account/blob/22c9d54b07f948f191d0f9075441fac462c39984/eth_account/messages.py#L270

func TestEIP712Json(t *testing.T) {
	saltHex := "646563616662656566" // hex for 'decafbeef'
	saltBytes, _ := hex.DecodeString(saltHex)

	var salt [32]byte
	copy(salt[:], saltBytes)
	saltHexString := "0x" + hex.EncodeToString(salt[:])

	domainData := apitypes.TypedDataDomain{
		Name:              "Ether Mail",
		Version:           "1",
		ChainId:           (*math.HexOrDecimal256)(big.NewInt(1)),
		VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		Salt:              saltHexString,
	}

	types := apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
			{Name: "salt", Type: "bytes32"},
		},
		"Person": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "wallet", Type: "address"},
		},
		"Mail": []apitypes.Type{
			{Name: "from", Type: "Person"},
			{Name: "to", Type: "Person"},
			{Name: "contents", Type: "string"},
		},
	}

	message := map[string]interface{}{
		"from": map[string]interface{}{
			"name":   "Cow",
			"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
		},
		"to": map[string]interface{}{
			"name":   "Bob",
			"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
		},
		"contents": "Hello, Bob!",
	}

	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: "Mail",
		Domain:      domainData,
		Message:     message,
	}

	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		t.Fatalf("Failed to hash typed data: %v", err)
	}

	// Expected hash from the eth-account library test case
	expectedHashHex := "0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530"
	expectedHash := common.HexToHash(expectedHashHex).Bytes()

	if hex.EncodeToString(hash) != hex.EncodeToString(expectedHash) {
		t.Fatalf("Hash mismatch:\nExpected: %s\nGot:      %s",
			expectedHashHex,
			"0x"+hex.EncodeToString(hash))
	} else {
		fmt.Printf("Test passed! Hash matches expected value: %s\n", expectedHashHex)
	}

	testKey := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	privateKey, _ := crypto.HexToECDSA(testKey[2:]) // Remove 0x prefix
	signer := &ecdsaSigner{privateKey}

	signature, err := signer.sign(hash)
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	fmt.Printf("Signature: %s\n", hex.EncodeToString(signature))

	// For signature verification, we need to handle the recovery ID correctly
	recoveryID := signature[64] - 27 // Convert from Ethereum's +27 format to the standard format
	adjustedSignature := make([]byte, 65)
	copy(adjustedSignature[:64], signature[:64])
	adjustedSignature[64] = recoveryID

	pubkey, err := crypto.Ecrecover(crypto.Keccak256(hash), adjustedSignature)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	recoveredPubKey, err := crypto.UnmarshalPubkey(pubkey)
	if err != nil {
		t.Fatalf("Failed to unmarshal public key: %v", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)
	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)

	if recoveredAddr != expectedAddr {
		t.Fatalf("Address mismatch: expected %s, got %s", expectedAddr.Hex(), recoveredAddr.Hex())
	} else {
		fmt.Printf("Signature verification successful. Recovered address: %s\n", recoveredAddr.Hex())
	}
}
