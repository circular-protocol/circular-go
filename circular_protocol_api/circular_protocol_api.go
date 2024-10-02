package circular_protocol_api

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/circular-protocol/circular_go/utils"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const __version__ = "1.0.8"

var __NAG_URL__ = "https://nag.circularlabs.io/NAG.php?cep="
var __NAG_KEY__ = ""
var __lastError__ = ""

func setNAGKey(key string) {
	__NAG_KEY__ = key
}

func getNAGKey() string {
	return __NAG_KEY__
}

func setNAGURL(url string) {
	__NAG_URL__ = url
}

func getNAGURL() string {
	return __NAG_URL__
}

/* 			SMART CONTRACT FUNCTIONS			*/

/* Test the execution of the smart contract
* @param blockchain string - blockchain to test
* @param contract string - contract to test
* @param data interface{} - data to send
* @return map[string]interface{} - response
* @return error - error
 */
func TestContract(blockchain string, sender string, project string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"From":       utils.HexFix(sender),
		"Timestamp":  utils.GetFormattedTimestamp(),
		"Project":    project,
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.TEST_CONTRACT, __NAG_URL__)
}

/* Call a function written on a smart contract
* @param blockchain string - blockchain to test
* @param from string - own wallet address
* @param project string - smart contract's address
* @param request string - plain text request function
* @return map[string]interface{} - response
* @return error - error
 */
func CallContract(blockchain string, from string, project string, request string) map[string]interface{} {

	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"From":       utils.HexFix(from),
		"Timestamp":  utils.GetFormattedTimestamp(),
		"Request":    utils.StringToHex(request),
		"Version":    __version__,
	}

	return utils.SendRequest(data, utils.CALL_CONTRACT, __NAG_URL__)
}

/* 			WALLET FUNCTIONS			*/

/*
* Check if a wallet is valid
* @param blockchain string - blockchain to check
* @param address string - address to check
* @return map[string]interface{} - response
* @return error - error
 */
func CheckWallet(blockchain string, address string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.CHECK_WALLET, __NAG_URL__)
}

/*
* Get information about a wallet
* @param blockchain string - blockchain to check
* @param address string - address to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetWallet(blockchain string, address string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_WALLET, __NAG_URL__)
}

/* Get the wallet nonce
* @param blockchain string - blockchain to check
* @param address string - address to check
* @return map[string]interface{} - response
 */
func GetWalletNonce(blockchain string, address string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_WALLET_NONCE, __NAG_URL__)
}

/* Get latest transactions of a wallet
* @param blockchain string - blockchain to check
* @param address string - address to check
* @return map[string]interface{} - response
 */
func GetLatestTransaction(blockchain string, address string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_LATEST_TRANSACTIONS, __NAG_URL__)
}

/* Get the balance of a wallet
* @param blockchain string - blockchain to check
* @param address string - address to check
* @param asset string - asset to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetWalletBalance(blockchain string, address string, asset string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"Asset":      utils.HexFix(asset),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_WALLET_BALANCE, __NAG_URL__)
}

/* Register a wallet
* @param blockchain string - blockchain to check
* @param address string - address to check
* @return id string - transaction ID
* @return error - error
 */
func RegisterWallet(blockchain string, publicKey string) (string, error) {
	blockchain = utils.HexFix(blockchain)
	publicKey = utils.HexFix(publicKey)

	var sender = utils.Sha256(publicKey)
	var to = sender
	var nonce = "0"
	var Type = "C_TYPE_REGISTERWALLET"
	var payloadObj = map[string]interface{}{
		"Action":    "CP_REGISTERWALLET",
		"PublicKey": publicKey,
	}

	jsonData, err := json.Marshal(payloadObj)
	if err != nil {
		return "", fmt.Errorf("errore nella codifica JSON: %w", err)
	}

	payload := hex.EncodeToString(jsonData)

	timestamp := utils.GetFormattedTimestamp()

	dataToHash := blockchain + sender + to + payload + nonce + timestamp

	id := utils.Sha256(dataToHash)
	signature := ""

	SendTransaction(id, sender, to, timestamp, Type, payload, nonce, signature, blockchain)

	return id, nil

}

/* 			DOMAIN MANAGEMENT			*/

/* Resolves the domain name returning the wallet address associated to the domain name
* a single wallet can be associated to multiple domain names
* @param blockchain string - blockchain to check
* @param name string - domain to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetDomain(blockchain string, name string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Name":       utils.HexFix(name),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_DOMAIN, __NAG_URL__)
}

/* 			ASSET MANAGEMENT			*/

/* Get the list of assets
* @param blockchain string - blockchain to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetAssetList(blockchain string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_ASSET_LIST, __NAG_URL__)
}

/* Get the asset description
* @param blockchain string - blockchain to check
* @param asset string - asset to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetAsset(blockchain string, asset string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Asset":      utils.HexFix(asset),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_ASSET, __NAG_URL__)
}

/* Get the asset supply
* @param blockchain string - blockchain to check
* @param asset string - asset to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetAssetSupply(blockchain string, asset string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Asset":      utils.HexFix(asset),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_ASSET_SUPPLY, __NAG_URL__)
}

/* Get the voucher
* @param blockchain string - blockchain to check
* @param code string - voucher code
* @return map[string]interface{} - response
* @return error - error
 */
func GetVoucher(blockchain string, code string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Code":       utils.HexFix(code),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_VOUCHER, __NAG_URL__)
}

/* 			BLOCKCHAIN MANAGEMENT			*/

/* Get the block range
* @param blockchain string - blockchain to check
* @param start int - start block
* @param end int - end block
* @return map[string]interface{} - response
* @return error - error
 */
func GetBlockRange(blockchain string, start int, end int) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Start":      start,
		"End":        end,
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_BLOCK_RANGE, __NAG_URL__)
}

/* Get the block
* @param blockchain string - blockchain to check
* @param number int - block to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetBlock(blockchain string, number int) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain":  utils.HexFix(blockchain),
		"BlockNumber": number,
		"Version":     __version__,
	}
	return utils.SendRequest(data, utils.GET_BLOCK, __NAG_URL__)
}

/* Get the block count
* @param blockchain string - blockchain to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetBlockCount(blockchain string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_BLOCK_COUNT, __NAG_URL__)
}

/* Get the analytics
* @param blockchain string - blockchain to check
* @return map[string]interface{} - response
* @return error - error
 */
func GetAnalytics(blockchain string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_ANALYTICS, __NAG_URL__)
}

/* Get the blockchains
* @return map[string]interface{} - response
* @return error - error
 */
func GetBlockchains() map[string]interface{} {
	data := map[string]interface{}{}

	return utils.SendRequest(data, utils.GET_BLOCKCHAINS, __NAG_URL__)
}

/*      		TRANSACTION MANAGEMENT			*/

/* Get the pending transaction
* @param blockchain string - blockchain to check
* @param TxID string - transaction ID
* @return map[string]interface{} - response
* @return error - error
 */
func GetPendingTransaction(blockchain string, TxID string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"ID":         utils.HexFix(TxID),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_PENDING_TRANSACTION, __NAG_URL__)
}

/* Get the transaction by ID
* @param blockchain string - blockchain to check
* @param TxID string - transaction ID
* @param start string - start block
* @param end string - end block
* @return map[string]interface{} - response
* @return error - error
*
* If end = 0 then start is the number of blocks form the last one minted
 */
func GetTransactionByID(blockchain string, TxID string, start string, end string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"ID":         utils.HexFix(TxID),
		"Start":      start,
		"End":        end,
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_TRANSACTION_BY_ID, __NAG_URL__)
}

/* Get the transaction by node
* @param blockchain string - blockchain to check
* @param node string - node to check
* @param start string - start block
* @param end string - end block
* @return map[string]interface{} - response
* @return error - error
*
* If end = 0 then start is the number of blocks form the last one minted
 */
func GetTransactionByNode(blockchain string, node string, start string, end string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"NodeID":     utils.HexFix(node),
		"Start":      start,
		"End":        end,
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_TRANSACTION_BY_NODE, __NAG_URL__)
}

/* Searches all transactions involving a specific address
* @param blockchain string - blockchain to check
* @param address string - address to check
* @param start string - start block
* @param end string - end block
* @return map[string]interface{} - response
* @return error - error
*
* If end = 0 then start is the number of blocks form the last one minted
 */
func GetTransactionByAddress(blockchain string, address string, start string, end string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"Start":      start,
		"End":        end,
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_TRANSACTIONS_BY_ADDRESS, __NAG_URL__)
}

/* Searches all transactions involving a speciied address in a specified timeframe
* @param blockchain string - blockchain to check
* @param address string - address to check
* @param startDate string - start block
* @param endDate string - end block
* @return map[string]interface{} - response
* @return error - error
 */
func GetTransactionByDate(blockchain string, address string, startDate string, endDate string) map[string]interface{} {
	data := map[string]interface{}{
		"Blockchain": utils.HexFix(blockchain),
		"Address":    utils.HexFix(address),
		"StartDate":  startDate,
		"EndDate":    endDate,
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.GET_TRANSACTION_BY_DATE, __NAG_URL__)
}

/* Send a transaction to a blockchain
* @param id string - transaction ID
* @param sender string - sender address
* @param to string - receiver address
* @param timeStamp string - time of the transaction
* @param type string - type of the transaction
* @param payload string - payload of the transaction
* @param nonce string - nonce of the transaction
* @param signature string - signature of the transaction
* @param blockchain string - blockchain to check
* @return id string - transaction ID
* @return error - error
 */
func SendTransaction(id string, sender string, to string, timeStamp string, transactionType string, payload string, nonce string, signature string, blockchain string) map[string]interface{} {
	data := map[string]interface{}{
		"ID":         utils.HexFix(id),
		"From":       utils.HexFix(sender),
		"To":         utils.HexFix(to),
		"Timestamp":  timeStamp,
		"Type":       transactionType,
		"Payload":    payload,
		"Nonce":      nonce,
		"Signature":  signature,
		"Blockchain": utils.HexFix(blockchain),
		"Version":    __version__,
	}
	return utils.SendRequest(data, utils.SEND_TRANSACTION, __NAG_URL__)
}

/* Send a transaction using the private key.
* @param from string - sender's wallet address
* @param privateKey string - sender's private key
* @param to - receiver's wallet address
* @param payload - payload in a Golang map object
* @param blockchain - blockchain's address
* @param type - transaction type
* @return id string - transaction ID
* @return error - error
 */
func SendTransactionWithPK(from string, privateKey string, to string, payload map[string]interface{}, blockchain string, transactionType string) map[string]interface{} {

	from = utils.HexFix(from)
	privateKey = utils.HexFix(privateKey)
	to = utils.HexFix(to)
	blockchain = utils.HexFix(blockchain)

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return map[string]interface{}{
			"Error": "Wrong payload format",
		}
	}
	hexPayload := utils.StringToHex(string(jsonPayload))

	response := GetWalletNonce(blockchain, from)
	responseMap, ok := response["Response"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{
			"Error": "Invalid response format from GetWalletNonce",
		}
	}

	nonceFloat, ok := responseMap["Nonce"].(float64)
	if !ok {
		return map[string]interface{}{
			"Error": "Nonce not found in response",
		}
	}

	nonce := int(nonceFloat)
	newNonce := strconv.Itoa(nonce + 1)

	timestamp := utils.GetFormattedTimestamp()
	dataToHash := blockchain + from + to + hexPayload + newNonce + timestamp
	id := utils.Sha256(dataToHash)

	bytesPrivateKey, err := hex.DecodeString(privateKey)
	if err != nil {
		return map[string]interface{}{
			"Error": "Error during the decoding of the private key", "Details": err,
		}
	}

	privKey := secp256k1.PrivKeyFromBytes(bytesPrivateKey)
	messageHash := chainhash.HashB([]byte(id))
	r, s, err := ecdsa.Sign(rand.Reader, privKey.ToECDSA(), messageHash)
	if err != nil {
		return map[string]interface{}{
			"Error": "Error during the signature", "Details": err,
		}
	}
	type ECDSASignature struct {
		R, S *big.Int
	}

	derSignature, err := asn1.Marshal(ECDSASignature{R: r, S: s})

	if err != nil {
		return map[string]interface{}{
			"Error": "Error during the DER conversion", "Details": err,
		}
	}

	stringDERSignature := hex.EncodeToString(derSignature)

	pubKey := privKey.PubKey()
	if !ecdsa.Verify(pubKey.ToECDSA(), messageHash, r, s) {
		return map[string]interface{}{
			"Error": "Signature verification failed",
		}
	}

	response = SendTransaction(id, from, to, timestamp, transactionType, hexPayload, newNonce, stringDERSignature, blockchain)
	return response
}

/* Recursive transaction finality polling
* will search a transaction every intervalSec seconds witha  desired timeout
* @param blockchain string - blockchain to check
* @param TxID string - transaction ID
* @param intervalSec int - interval in seconds
* @param timeoutSec int - timeout in seconds
* @return map[string]interface{} - response
* @return error - error
 */
func GetTransactionOutcome(Blockchain string, TxID string, timeoutSec int, intervalSec int) string {
	startTime := time.Now()
	interval := time.Duration(intervalSec) * time.Second
	timeout := time.Duration(timeoutSec) * time.Second
	var checkTransaction func() string
	checkTransaction = func() string {
		elapsedTime := time.Since(startTime)
		fmt.Println("Checking transaction...", elapsedTime, timeout)
		if elapsedTime > timeout {
			fmt.Println("Timeout exceeded")
			return "Timeout exceeded"
		}
		// Get the transaction
		data := GetTransactionByID(Blockchain, TxID, "0", "10")

		fmt.Println("Data received:", data)
		if data["Result"] == 200 && data["Response"] != "Transaction Not Found" && data["Response"].(string) != "Pending" {
			return data["Response"].(string)
		}
		fmt.Println("Transaction not yet confirmed or not found, polling again...")
		time.Sleep(interval)
		return checkTransaction() //Recursive call
	}
	return checkTransaction()
}