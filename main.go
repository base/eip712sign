package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/base/eip712sign/usbwallet"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/exp/slices"
)

func main() {
	var privateKey string
	var ledger bool
	var index int
	var address bool
	var mnemonic string
	var hdPath string
	var data string
	var prefix string
	var suffix string
	var workdir string
	var skipSender bool
	var jsonInput bool
	flag.StringVar(&privateKey, "private-key", "", "Private key to use for signing")
	flag.BoolVar(&ledger, "ledger", false, "Use ledger device for signing")
	flag.IntVar(&index, "index", 0, "Index of the ledger to use")
	flag.BoolVar(&address, "address", false, "Print address of signer and exit")
	flag.StringVar(&mnemonic, "mnemonic", "", "Mnemonic to use for signing")
	flag.StringVar(&hdPath, "hd-paths", "m/44'/60'/0'/0/0", "Hierarchical deterministic derivation path for mnemonic or ledger")
	flag.StringVar(&data, "data", "", "Data to be signed")
	flag.StringVar(&prefix, "prefix", "vvvvvvvv", "String that prefixes the data to be signed")
	flag.StringVar(&suffix, "suffix", "^^^^^^^^", "String that suffixes the data to be signed")
	flag.StringVar(&workdir, "workdir", ".", "Directory in which to run the subprocess")
	flag.BoolVar(&skipSender, "skip-sender", false, "Skip adding the --sender flag to forge script commands")
	flag.BoolVar(&jsonInput, "json", false, "Treat input as EIP-712 JSON payload")
	flag.Parse()

	options := 0
	if privateKey != "" {
		options++
	}
	if ledger {
		options++
	}
	if mnemonic != "" {
		options++
	}
	if options != 1 {
		log.Fatalf("One (and only one) of --private-key, --ledger, --mnemonic must be set")
	}

	// signer creation error is handled later, allowing the command that generates the signable
	// data to run without a key / ledger, which is useful for simulation purposes
	s, signerErr := createSigner(privateKey, mnemonic, hdPath, index)
	if signerErr != nil {
		if address {
			log.Fatalf("Error creating signer: %v", signerErr)
		}
		log.Printf("Warning: signer creation failed: %v", signerErr)
	}

	if address {
		fmt.Printf("Signer: %s\n", s.address().String())
		os.Exit(0)
	}

	var input []byte
	var err error
	if data != "" {
		input = []byte(data)
	} else if flag.NArg() == 0 {
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Error reading from stdin: %v", err)
		}
	} else {
		args := flag.Args()
		if !skipSender && args[0] == "forge" && args[1] == "script" && !slices.Contains(args, "--sender") && s != nil {
			args = append(args, "--sender", s.address().String())
		}
		fmt.Printf("Running '%s\n", strings.Join(args, " "))
		input, err = run(workdir, args[0], args[1:]...)
		if err != nil {
			log.Fatalf("Error running process: %v", err)
		}
		fmt.Printf("\n%s exited with code 0\n", flag.Arg(0))
	}

	if index := strings.Index(string(input), prefix); prefix != "" && index >= 0 {
		input = input[index+len(prefix):]
	}
	if index := strings.Index(string(input), suffix); suffix != "" && index >= 0 {
		input = input[:index]
	}

	var hash []byte
	if jsonInput {
		// Process as EIP-712 JSON payload
		var typedData apitypes.TypedData
		if err := json.Unmarshal(input, &typedData); err != nil {
			log.Fatalf("Error parsing EIP-712 JSON payload: %v", err)
		}

		hash, _, err = apitypes.TypedDataAndHash(typedData)
		if err != nil {
			log.Fatalf("Error generating EIP-712 hash: %v", err)
		}

		domainSeparator, _ := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
		messageHash, _ := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
		fmt.Printf("Domain hash: 0x%s\n", hex.EncodeToString(domainSeparator))
		fmt.Printf("Message hash: 0x%s\n", hex.EncodeToString(messageHash))
	} else {
		// Process as already hashed hex string
		hash = common.FromHex(strings.TrimSpace(string(input)))
		if len(hash) != 66 {
			log.Fatalf("Expected EIP-712 hex string with 66 bytes, got %d bytes. Add the --json flag to process unhashed payloads. Value: %s", len(hash), string(input))
		}

		domainHash := hash[2:34]
		messageHash := hash[34:66]
		fmt.Printf("Domain hash: 0x%s\n", hex.EncodeToString(domainHash))
		fmt.Printf("Message hash: 0x%s\n", hex.EncodeToString(messageHash))
	}

	if signerErr != nil {
		log.Fatalf("Error creating signer: %v", signerErr)
	}

	fmt.Printf("Signing as: %s\n\n", s.address().String())

	if ledger {
		fmt.Printf("Data sent to ledger, awaiting signature...")
	}
	signature, err := s.sign(hash)
	if err == accounts.ErrWalletClosed {
		// ledger is flaky sometimes, recreate and retry
		fmt.Printf("failed with %s, retrying...", err.Error())
		s, err = createSigner(privateKey, mnemonic, hdPath, index)
		if err != nil {
			log.Fatalf("Error creating signer: %v", err)
		}
		signature, err = s.sign(hash)
	}
	if ledger {
		fmt.Println("done")
	}
	if err != nil {
		log.Fatalf("Error signing data: %v", err)
	}

	fmt.Printf("\nData: 0x%s\n", hex.EncodeToString(hash))
	fmt.Printf("Signer: %s\n", s.address().String())
	fmt.Printf("Signature: %s\n", hex.EncodeToString(signature))
}

func run(workdir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = workdir

	var buffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &buffer)
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	return buffer.Bytes(), err
}

func createSigner(privateKey, mnemonic, hdPath string, index int) (signer, error) {
	path, err := accounts.ParseDerivationPath(hdPath)
	if err != nil {
		return nil, err
	}

	if privateKey != "" {
		key, err := crypto.HexToECDSA(privateKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing private key: %w", err)
		}
		return &ecdsaSigner{key}, nil
	}

	if mnemonic != "" {
		key, err := derivePrivateKey(mnemonic, path)
		if err != nil {
			return nil, fmt.Errorf("error deriving key from mnemonic: %w", err)
		}
		return &ecdsaSigner{key}, nil
	}

	// assume using a ledger
	ledgerHub, err := usbwallet.NewLedgerHub()
	if err != nil {
		return nil, fmt.Errorf("error starting ledger: %w", err)
	}
	wallets := ledgerHub.Wallets()
	if len(wallets) == 0 {
		return nil, fmt.Errorf("no ledgers found, please connect your ledger")
	} else if len(wallets) > 1 {
		fmt.Printf("Found %d ledgers, using index %d\n", len(wallets), index)
	}
	if index < 0 || index >= len(wallets) {
		return nil, fmt.Errorf("ledger index out of range")
	}
	wallet := wallets[index]
	if err := wallet.Open(""); err != nil {
		return nil, fmt.Errorf("error opening ledger: %w", err)
	}
	account, err := wallet.Derive(path, true)
	if err != nil {
		return nil, fmt.Errorf("error deriving ledger account (please unlock and open the Ethereum app): %w", err)
	}
	return &walletSigner{
		wallet:  wallet,
		account: account,
	}, nil
}

type signer interface {
	address() common.Address
	sign([]byte) ([]byte, error)
}

type ecdsaSigner struct {
	*ecdsa.PrivateKey
}

func (s *ecdsaSigner) address() common.Address {
	return crypto.PubkeyToAddress(s.PublicKey)
}

func (s *ecdsaSigner) sign(data []byte) ([]byte, error) {
	sig, err := crypto.Sign(crypto.Keccak256(data), s.PrivateKey)
	if err != nil {
		return nil, err
	}
	sig[crypto.RecoveryIDOffset] += 27
	return sig, err
}

type walletSigner struct {
	wallet  accounts.Wallet
	account accounts.Account
}

func (s *walletSigner) address() common.Address {
	return s.account.Address
}

func (s *walletSigner) sign(data []byte) ([]byte, error) {
	return s.wallet.SignData(s.account, accounts.MimetypeTypedData, data)
}

func derivePrivateKey(mnemonic string, path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	// Parse the seed string into the master BIP32 key.
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, err
	}

	privKey, err := hdkeychain.NewMaster(seed, fakeNetworkParams{})
	if err != nil {
		return nil, err
	}

	for _, child := range path {
		privKey, err = privKey.Child(child)
		if err != nil {
			return nil, err
		}
	}

	rawPrivKey, err := privKey.SerializedPrivKey()
	if err != nil {
		return nil, err
	}

	return crypto.ToECDSA(rawPrivKey)
}

type fakeNetworkParams struct{}

func (f fakeNetworkParams) HDPrivKeyVersion() [4]byte {
	return [4]byte{}
}

func (f fakeNetworkParams) HDPubKeyVersion() [4]byte {
	return [4]byte{}
}
