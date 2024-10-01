package main

import (
	"fmt"

	"github.com/dannydenovi/circular_go/circular"
)

func main() {
	var blockchain = "0x8a20baa40c45dc5055aeb26197c203e576ef389d9acb171bd62da11dc5ad72b2"
	var test_addr = ""
	var private_key = ""

	var payload = map[string]interface{}{
		"Action": "CP_SEND",
		"Asset":  "CIRX",
		"Amount": "1",
		"Memo":   "Test transaction",
	}

	result := circular.SendTransactionWithPK(test_addr, private_key, test_addr, payload, blockchain, "C_TYPE_COIN")

	fmt.Println(result)
}
