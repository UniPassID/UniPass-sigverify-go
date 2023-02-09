package unipass_sigverify

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"golang.org/x/crypto/sha3"
)

// 0x1626ba7e
var EIP1271_SELECTOR = [32]byte{22, 38, 186, 126}

const UnipassMessagePrefix = "\x18UniPass Signed Message:\n"
const EIP191MessagePrefix = "\x19Ethereum Signed Message:\n"

const IsValidSignatureABI = "[{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_hash\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"_signature\",\"type\":\"bytes\"}],\"name\":\"isValidSignature\",\"outputs\":[{\"internalType\":\"bytes4\",\"name\":\"magicValue\",\"type\":\"bytes4\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"

func UnipassHashMessage(message []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(UnipassMessagePrefix))
	hasher.Write([]byte(strconv.Itoa(len(message))))
	hasher.Write(message)
	return hasher.Sum(nil)
}

func EIP191HashMessage(message []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(EIP191MessagePrefix))
	hasher.Write([]byte(strconv.Itoa(len(message))))
	hasher.Write(message)
	return hasher.Sum(nil)
}

func VerifySignature(
	ctx context.Context,
	account common.Address,
	msgHash [32]byte,
	sig []byte,
	client *ethclient.Client) (bool, error) {
	if len(sig) == 65 {
		recoveredPubkey, err := crypto.SigToPub(msgHash[:], sig)
		if err != nil {
			log.Fatal(err)
		}

		recoveredAddr := crypto.PubkeyToAddress(*recoveredPubkey)

		if recoveredAddr == account {
			return true, nil
		}
	}

	if client != nil {
		accountABI, err := abi.JSON(strings.NewReader(IsValidSignatureABI))
		if err != nil {
			return false, err
		}
		callData, err := accountABI.Pack("isValidSignature", msgHash, sig)
		if err != nil {
			return false, err
		}
		result, err := client.CallContract(ctx, ethereum.CallMsg{
			To:   &account,
			Data: callData,
		}, nil)
		if err != nil {
			return false, err
		}

		return bytes.Equal(result, EIP1271_SELECTOR[:]), nil
	}

	return false, errors.New("signature verify failed")
}

func VerifyMessageSignature(
	ctx context.Context,
	account common.Address,
	msg, sig []byte,
	isEIP191 bool,
	client *ethclient.Client) (bool, error) {
	msgHash := [32]byte{}
	if isEIP191 {
		messageHash := EIP191HashMessage(msg)
		copy(msgHash[:], messageHash)
	} else {
		messageHash := UnipassHashMessage(msg)
		copy(msgHash[:], messageHash)
	}
	return VerifySignature(ctx, account, msgHash, sig, client)
}

func VerifySignedTypedData(
	ctx context.Context,
	account common.Address,
	data apitypes.TypedData,
	sig []byte,
	client *ethclient.Client) (bool, error) {
	msgHash := [32]byte{}
	messageHash, _, err := apitypes.TypedDataAndHash(data)
	if err != nil {
		return false, err
	}
	copy(msgHash[:], messageHash)
	return VerifySignature(ctx, account, msgHash, sig, client)
}
