# UniPass-sigverify-go

there are two methods you can use to verify signature signed by a eoa accout or UniPass wallet account.

`func VerifyMessageSignature(ctx context.Context, account common.Address, msg, sig []byte, isEIP191 bool, client *ethclient.Client) (bool, error)`

`func VerifySignedTypedData(ctx context.Context, account common.Address, data apitypes.TypedData, sig []byte, client *ethclient.Client) (bool, error)`