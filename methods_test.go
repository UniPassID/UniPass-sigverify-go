package unipass_sigverify

import (
	"context"
	"log"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func TestVerifyMessageSignature(t *testing.T) {
	client, err := ethclient.Dial("https://rpc.ankr.com/polygon_mumbai")

	if err != nil {
		log.Panicf("client connect error:%v", err)
	}
	ctx := context.Background()
	account := common.HexToAddress("0x6939dBfaAe305FCdA6815ebc9a297997969d39aB")

	sig := common.FromHex("0x000001d0bdf2f92cfc6de71d00ca5413c19500ae912b215ca680bff55d2c4e971401fd2852989416ea19622985bfb57e341aa7875b17aae708dc0c03375250181ac1da1c020000003c000000640000000002007e7649ccd0315628dabe5256cd050d4ce7e1824d1217dba20cc5e3e5626553970000003c000000000000003c0000c06495b106de8a0701ff5e84d9f8a5c9d711b1b6000000280000000000000000")
	msg := []byte("Welcome to UniPass!")
	ok, err := VerifyMessageSignature(ctx, account, msg, sig, false, client)
	if err != nil || !ok {
		t.Fatalf("validate signature error:%s", err)
	}
}

func TestVerifySignedTypeData(t *testing.T) {
	client, err := ethclient.Dial("https://rpc.ankr.com/polygon_mumbai")
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	account := common.HexToAddress("0x6939dBfaAe305FCdA6815ebc9a297997969d39aB")
	{
		chainId := math.HexOrDecimal256(*common.Big1)
		data :=
			apitypes.TypedData{
				Types: apitypes.Types{
					"EIP712Domain": []apitypes.Type{
						{Name: "name", Type: "string"},
						{Name: "version", Type: "string"},
						{Name: "chainId", Type: "uint256"},
						{Name: "verifyingContract", Type: "address"},
					},
					"Person": []apitypes.Type{
						{Name: "name", Type: "string"},
						{Name: "wallet", Type: "address"},
					},
					"Mail": []apitypes.Type{
						{Name: "from", Type: "Person"},
						{Name: "to", Type: "Person"},
						{Name: "contents", Type: "string"},
					}},
				Domain: apitypes.TypedDataDomain{
					Name:              "Ether Mail",
					Version:           "1",
					ChainId:           &chainId,
					VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
				},
				PrimaryType: "Mail",
				Message: apitypes.TypedDataMessage{
					"from":     apitypes.TypedDataMessage{"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
					"to":       apitypes.TypedDataMessage{"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
					"contents": "Hello, Bob!",
				},
			}
		sig := common.FromHex("0x0000018e9e9a0bd86c21c33ad96c875f976b9c9fdb78a110536d9b09b74e9d985d2eb04da24f23a78e4c9f281ecdd8869f50a2b5b4e18e4ec78cfcedf3ff3a973fb5dc1c020000003c000000640000000002007e7649ccd0315628dabe5256cd050d4ce7e1824d1217dba20cc5e3e5626553970000003c000000000000003c0000c06495b106de8a0701ff5e84d9f8a5c9d711b1b6000000280000000000000000")
		ok, err := VerifySignedTypedData(ctx, account, data, sig, client)
		if err != nil || !ok {
			t.Fatalf("validate signature error:%s", err)
		}
	}
}
