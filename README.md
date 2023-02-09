# UniPass-sigverify-go

there are two methods you can use to verify signature signed by a eoa accout or UniPass wallet account.

```go
//  Verify ethereum account signature, including EOA account and Contract account.
// - parameter
//  - param ctx
//  - param account: account address.
//  - param message.
//  - param signature.
//  - param isEIP191Prefix boolean: Does the personal hash algorithm use EIP191 prefix.
//                       There are two message prefix for personal hash algorithm during signing:
//                                    - EIP191Prefix: `\x19Ethereum Signed Message:\n`
//                                    - UniPassPrefix: `\x18UniPass Signed Message:\n`
//   - param client: optional param, for contract signature validation
//   - returns signature validation result and error message
func VerifyMessageSignature(
	ctx context.Context,
	account common.Address,
	message, signature []byte,
	isEIP191 bool,
	client *ethclient.Client) (bool, error)


//  Verify typedData signature, including EOA account and Contract account.
// - parameter
//  - param ctx
//  - param account: account address.
//  - param data.
//  - param signature.
//  - param client: optional param, for contract signature validation
//  - returns signature validation result and error message
func VerifyTypedDataSignature(
	ctx context.Context,
	account common.Address,
	data apitypes.TypedData,
	signature []byte,
	client *ethclient.Client) (bool, error)
```