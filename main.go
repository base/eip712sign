package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/base/go-bip39"
	"github.com/base/usbwallet"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"golang.org/x/exp/slices"
)

func main() {
	var privateKey string
	var ledger bool
	var trezor bool
	var index int
	var address bool
	var mnemonic string
	var hdPath string
	var text bool
	var data string
	var prefix string
	var suffix string
	var workdir string
	var skipSender bool
	flag.StringVar(&privateKey, "private-key", "", "Private key to use for signing")
	flag.BoolVar(&ledger, "ledger", false, "Use ledger device for signing")
	flag.BoolVar(&trezor, "trezor", false, "Use trezor device for signing")
	flag.IntVar(&index, "index", 0, "Device index to use (if multiple devices are connected)")
	flag.BoolVar(&address, "address", false, "Print address of signer and exit")
	flag.StringVar(&mnemonic, "mnemonic", "", "Mnemonic to use for signing")
	flag.StringVar(&hdPath, "hd-paths", "m/44'/60'/0'/0/0", "Hierarchical deterministic derivation path for mnemonic, ledger, or trezor")
	flag.BoolVar(&text, "text", false, "Use EIP-191 message format for signing (default is EIP-712)")
	flag.StringVar(&data, "data", "", "Data to be signed")
	flag.StringVar(&prefix, "prefix", "vvvvvvvv", "String that prefixes the data to be signed")
	flag.StringVar(&suffix, "suffix", "^^^^^^^^", "String that suffixes the data to be signed")
	flag.StringVar(&workdir, "workdir", ".", "Directory in which to run the subprocess")
	flag.BoolVar(&skipSender, "skip-sender", false, "Skip adding the --sender flag to forge script commands")
	flag.Parse()

	options := 0
	if privateKey != "" {
		options++
	}
	if ledger {
		options++
	}
	if trezor {
		options++
	}
	if mnemonic != "" {
		options++
	}
	if options != 1 {
		log.Fatalf("One (and only one) of --private-key, --ledger, --trezor, --mnemonic must be set")
	}

	// signer creation error is handled later, allowing the command that generates the signable
	// data to run without a key / ledger / trezor, which is useful for simulation purposes
	s, signerErr := createSigner(privateKey, mnemonic, hdPath, index, ledger, trezor)
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
	fmt.Println()

	if index := bytes.Index(input, []byte(prefix)); prefix != "" && index >= 0 {
		input = input[index+len(prefix):]
	}
	if index := bytes.Index(input, []byte(suffix)); suffix != "" && index >= 0 {
		input = input[:index]
	}
	input = bytes.TrimSpace(input)

	var typedData *apitypes.TypedData
	if bytes.HasPrefix(input, []byte("0x")) {
		input = common.FromHex(string(input))
	}
	if bytes.HasPrefix(input, []byte("{")) && !text {
		typedData = new(apitypes.TypedData)
		if err := json.Unmarshal(input, typedData); err != nil {
			log.Fatalf("Error parsing typed data: %v", err)
		}
	}
	if typedData == nil && !text && len(input) != 66 {
		log.Fatalf("Expected EIP-712 hex string with 66 bytes, got %d bytes", len(input))
	}

	hashes := input
	if typedData != nil {
		_, hashesStr, err := apitypes.TypedDataAndHash(*typedData)
		if err != nil {
			log.Fatalf("Error hashing typed data: %v", err)
		}
		hashes = []byte(hashesStr)
	}
	if len(hashes) == 66 {
		fmt.Printf("Domain hash: 0x%x\n", hashes[2:34])
		fmt.Printf("Message hash: 0x%x\n", hashes[34:66])
	}

	if signerErr != nil {
		log.Fatalf("Error creating signer: %v", signerErr)
	}

	fmt.Printf("Signing as: %s\n\n", s.address().String())

	if ledger || trezor {
		fmt.Printf("Data sent to device, awaiting signature...")
	}
	sign := func() ([]byte, error) {
		if text {
			return s.signText(input)
		}
		if typedData != nil {
			return s.signData(*typedData)
		}
		return s.signHash(input)
	}
	signature, err := sign()
	if errors.Is(err, accounts.ErrWalletClosed) {
		// ledger is flaky sometimes, recreate and retry
		fmt.Printf("failed with %s, retrying...", err.Error())
		s, err = createSigner(privateKey, mnemonic, hdPath, index, ledger, trezor)
		if err != nil {
			log.Fatalf("Error creating signer: %v", err)
		}
		signature, err = sign()
	}
	if ledger || trezor {
		fmt.Println("done")
	}
	if err != nil {
		log.Fatalf("Error signing data: %v", err)
	}

	fmt.Println()
	if typedData != nil {
		fmt.Printf("Typed: 0x%x\n", input)
	}
	fmt.Printf("Data: 0x%x\n", hashes)
	fmt.Printf("Signer: %s\n", s.address().String())
	fmt.Printf("Signature: %x\n", signature)
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

func createSigner(privateKey, mnemonic, hdPath string, index int, ledger, trezor bool) (signer, error) {
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

	// assume using a hardware wallet
	var hub *usbwallet.Hub
	if trezor {
		hub, err = usbwallet.NewTrezorHubWithWebUSB()
		if err != nil {
			return nil, fmt.Errorf("error starting trezor: %w", err)
		}
	} else if ledger {
		hub, err = usbwallet.NewLedgerHub()
		if err != nil {
			return nil, fmt.Errorf("error starting ledger: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no wallet type specified")
	}

	wallets := hub.Wallets()
	if len(wallets) == 0 {
		return nil, fmt.Errorf("no hardware wallets found, please connect your device")
	} else if len(wallets) > 1 {
		fmt.Printf("Found %d devices, using index %d\n", len(wallets), index)
	}
	if index < 0 || index >= len(wallets) {
		return nil, fmt.Errorf("device index out of range")
	}
	wallet := wallets[index]
	if err := wallet.Open(""); err != nil {
		return nil, fmt.Errorf("error opening device: %w", err)
	}
	account, err := wallet.Derive(path, true)
	if err != nil {
		return nil, fmt.Errorf("error deriving account (please unlock and open the Ethereum app): %w", err)
	}
	return &walletSigner{
		wallet:  wallet,
		account: account,
	}, nil
}

type signer interface {
	address() common.Address
	signHash(data []byte) ([]byte, error)
	signText(data []byte) ([]byte, error)
	signData(data apitypes.TypedData) ([]byte, error)
}

type ecdsaSigner struct {
	*ecdsa.PrivateKey
}

func (s *ecdsaSigner) address() common.Address {
	return crypto.PubkeyToAddress(s.PublicKey)
}

func (s *ecdsaSigner) signHash(data []byte) ([]byte, error) {
	return s.sign(crypto.Keccak256(data))
}

func (s *ecdsaSigner) signText(data []byte) ([]byte, error) {
	return s.sign(accounts.TextHash(data))
}

func (s *ecdsaSigner) signData(data apitypes.TypedData) ([]byte, error) {
	hash, _, err := apitypes.TypedDataAndHash(data)
	if err != nil {
		return nil, err
	}
	return s.sign(hash)
}

func (s *ecdsaSigner) sign(hash []byte) ([]byte, error) {
	sig, err := crypto.Sign(hash, s.PrivateKey)
	if err != nil {
		return nil, err
	}
	sig[crypto.RecoveryIDOffset] += 27
	return sig, err
}

type walletSigner struct {
	wallet  usbwallet.Wallet
	account accounts.Account
}

func (s *walletSigner) address() common.Address {
	return s.account.Address
}

func (s *walletSigner) signHash(data []byte) ([]byte, error) {
	return s.wallet.SignData(s.account, accounts.MimetypeTypedData, data)
}

func (s *walletSigner) signText(data []byte) ([]byte, error) {
	return s.wallet.SignText(s.account, data)
}

func (s *walletSigner) signData(data apitypes.TypedData) ([]byte, error) {
	return s.wallet.SignTypedData(s.account, data)
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
