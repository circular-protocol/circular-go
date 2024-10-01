package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

/* SendRequest sends an HTTP POST request with JSON data
* @param data interface{} - data to send
* @param nagFunction string - function to call
* @param nagURL string - URL to call
* @return map[string]interface{} - response
* @return error - error
 */
// SendRequest esegue una richiesta HTTP POST e gestisce la risposta JSON
func SendRequest(data interface{}, nagFunction string, nagURL string) map[string]interface{} {
	url := nagURL + nagFunction

	// Codifica i dati in JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		response := map[string]interface{}{
			"Error": "Wrong JSON format",
		}

		return response
	}

	// Crea la richiesta HTTP
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		response := map[string]interface{}{
			"Error": "Error during the creation of the request",
		}

		return response
	}
	req.Header.Set("Content-Type", "application/json")

	// Invia la richiesta HTTP
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		response := map[string]interface{}{
			"Error": "Error during the request",
		}

		return response
	}
	defer resp.Body.Close()

	// Legge e gestisce la risposta HTTP
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		response := map[string]interface{}{
			"Error": "Error during the reading of the response",
		}

		return response
	}

	if resp.StatusCode != http.StatusOK {
		response := map[string]interface{}{
			"Error": "Error during the request",
		}

		return response
	}

	var response map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		response := map[string]interface{}{
			"Error": "Error during the decoding of the response",
		}

		return response
	}

	return response
}

// PadNumber pads a number with leading zeros to number less than 10
func PadNumber(number int) string {
	if number < 10 {
		return fmt.Sprintf("0%d", number)
	}
	return fmt.Sprintf("%d", number)
}

// Generate formatted timestamp in the format YYYY-MM-DD-HH:MM:SS
func GetFormattedTimestamp() string {
	t := time.Now()
	return fmt.Sprintf("%d:%s:%s-%s:%s:%s", t.Year(), PadNumber(int(t.Month())), PadNumber(t.Day()), PadNumber(t.Hour()), PadNumber(t.Minute()), PadNumber(t.Second()))
}

// ECSignature defines the structure for DER encoded signature
type ECSignature struct {
	R, S *big.Int
}

/* // SignMessage firma un messaggio con una chiave privata in formato hex e restituisce la firma in formato hex.
func SignMessage(message string, privateKeyHex string) (string, error) {
	// Converti la chiave privata hex in formato binario
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key format: %v", err)
	}

	// Verifica che la lunghezza della chiave privata sia corretta
	if len(privateKeyBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}

	// Crea la chiave privata ECDSA
	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(), // Usa la curva secp256k1
			X:     big.NewInt(0),
			Y:     big.NewInt(0),
		},
		D: new(big.Int).SetBytes(privateKeyBytes),
	}

	// Calcola l'hash del messaggio
	hash := sha256.Sum256([]byte(message))

	// Calcola il nonce deterministico usando RFC 6979
	k := getDeterministicNonce(hash[:], privateKey.D)

	// Calcola la firma ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, &privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("error during the signature: %v", err)
	}

	// Codifica la firma nel formato DER
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return "", fmt.Errorf("error marshaling signature: %v", err)
	}

	// Converti la firma DER in una stringa hex
	hexSignature := hex.EncodeToString(sig)

	return hexSignature, nil
} */

/* // getDeterministicNonce genera un nonce deterministico secondo RFC 6979
func getDeterministicNonce(hash []byte, privateKey *big.Int) *big.Int {
	// Questa è una semplificazione. Dovresti implementare il vero RFC 6979 qui.
	// L'implementazione completa richiede un po' più di logica.

	// Usando un hash della chiave privata e del messaggio per determinare k
	h1 := sha256.New()
	h1.Write(privateKey.Bytes())
	h1.Write(hash)
	k := new(big.Int).SetBytes(h1.Sum(nil))

	// Assicurati che k sia valido per la curva (k deve essere in [1, n-1])
	n := elliptic.P256().Params().N
	k.Mod(k, n)
	if k.Cmp(big.NewInt(1)) < 0 {
		k.Set(big.NewInt(1))
	} else if k.Cmp(n) >= 0 {
		k.Set(new(big.Int).Sub(n, big.NewInt(1)))
	}

	return k
} */

// VerifySignature verifies a signature given a public key, message and signature
func VerifySignature(publicKey string, message string, signature []byte) bool {
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	hash := sha256.Sum256([]byte(message))

	x, y := big.NewInt(0), big.NewInt(0)
	publicKeyBytes, _ := hex.DecodeString(publicKey)
	publicKeyCurve := elliptic.P256()
	if len(publicKeyBytes) != 64 {
		return false
	}
	x.SetBytes(publicKeyBytes[:32])
	y.SetBytes(publicKeyBytes[32:])

	publicKeyStruct := ecdsa.PublicKey{
		Curve: publicKeyCurve,
		X:     x,
		Y:     y,
	}

	return ecdsa.Verify(&publicKeyStruct, hash[:], r, s)
}

func GetPublicKey(privateKey string) (string, error) {
	// Decodifica la chiave privata dalla sua rappresentazione esadecimale
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	// Genera una nuova chiave ECDSA utilizzando la curva ellittica P-256
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	// Imposta la parte segreta della chiave generata utilizzando la chiave privata fornita
	key.D = new(big.Int).SetBytes(privKeyBytes)

	// Ottiene la rappresentazione dei punti della chiave pubblica in formato compresso
	publicKeyBytes := elliptic.MarshalCompressed(key.Curve, key.X, key.Y)

	// Restituisce la chiave pubblica in formato esadecimale
	return hex.EncodeToString(publicKeyBytes), nil
}

// StringToHex converts a string to a hexadecimal string
func StringToHex(str string) string {
	return hex.EncodeToString([]byte(str))
}

// HexToString coneverts a hexadecimal string to a string
func HexToString(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// HexFix removes the prefix "0x"
func HexFix(word interface{}) string {
	switch v := word.(type) {
	case int:
		return fmt.Sprintf("%x", v)
	case string:
		if len(v) >= 2 && v[:2] == "0x" {
			return v[2:]
		}
		return v
	default:
		return ""
	}
}

// Sha256 calculates the SHA-256 hash of a string
func Sha256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// NAG FUNCTIONS

const TEST_CONTRACT = "Circular_TestContract_"
const CALL_CONTRACT = "Circular_CallContract_"
const CHECK_WALLET = "Circular_CheckWallet_"
const GET_WALLET = "Circular_GetWallet_"
const GET_LATEST_TRANSACTIONS = "Circular_GetLatestTransactions_"
const GET_WALLET_BALANCE = "Circular_GetWalletBalance_"
const REGISTER_WALLET = "Circular_RegisterWallet_"
const GET_DOMAIN = "Circular_GetDomain_"
const GET_ASSET_LIST = "Circular_GetAssetList_"
const GET_ASSET = "Circular_GetAsset_"
const GET_ASSET_SUPPLY = "Circular_GetAssetSupply_"
const GET_VOUCHER = "Circular_GetVoucher_"
const GET_BLOCK_RANGE = "Circular_GetBlockRange_"
const GET_BLOCK = "Circular_GetBlock_"
const GET_BLOCK_COUNT = "Circular_GetBlockCount_"
const GET_ANALYTICS = "Circular_GetAnalytics_"
const GET_BLOCKCHAINS = "Circular_GetBlockchains_"
const GET_PENDING_TRANSACTION = "Circular_GetPendingTransaction_"
const GET_TRANSACTION_BY_ID = "Circular_GetTransactionbyID_"
const GET_TRANSACTION_BY_NODE = "Circular_GetTransactionbyNode_"
const GET_TRANSACTIONS_BY_ADDRESS = "Circular_GetTransactionbyAddress_"
const GET_TRANSACTION_BY_DATE = "Circular_GetTransactionbyDate_"
const SEND_TRANSACTION = "Circular_AddTransaction_"
const GET_WALLET_NONCE = "Circular_GetWalletNonce_"
