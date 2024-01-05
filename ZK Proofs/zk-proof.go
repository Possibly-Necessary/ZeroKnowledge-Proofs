// Silly example of Zero Knowledge range proofs using the zkrp bullet proof library:
// https://pkg.go.dev/github.com/0xdecaf/zkrp@v0.0.0-20201019075642-eed3acf37c78

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/0xdecaf/zkrp/bulletproofs"
)

var wg sync.WaitGroup

// Merlin the prover
func Merlin(mta, atm chan []byte, wg *sync.WaitGroup) {

	// Defer control mechanism
	defer wg.Done()

	// Set up the range, [18, 1000) in this case
	params, _ := bulletproofs.SetupGeneric(18, 1000)

	// Merlin's age is 666
	fmt.Println("Merlin's age is 666 (his secret).")
	bigSecret := new(big.Int).SetInt64(int64(666))

	// Create the zero-knowledge range proof
	proof, _ := bulletproofs.ProveGeneric(bigSecret, params)

	// Encode the proof to JSON
	jsonEncoded, _ := json.Marshal(proof)

	// Send it to Arthur
	mta <- jsonEncoded

}

// Arthur the verifier
func Arthur(mta, atm chan []byte, wg *sync.WaitGroup) {

	// Defer control mechanism
	defer wg.Done()

	// Arthur recieves the encoded proof
	jEncoded := <-mta

	// Decode the proof from JSON
	var decodedProof bulletproofs.ProofBPRP
	_ = json.Unmarshal(jEncoded, &decodedProof)

	// Verify the proof
	ok, _ := decodedProof.Verify()

	if ok == true {
		fmt.Println("Arthur: Age verified to be in the range [18, 1000)")
	}

}

func main() {

	// Creating two communication channels for Arthur and Merlin
	MerlinToArthur := make(chan []byte, 10)
	ArthurToMerlin := make(chan []byte, 10)

	// Call Merlin and Arthur goroutines
	wg.Add(1)
	go Merlin(MerlinToArthur, ArthurToMerlin, &wg)

	wg.Add(1)
	go Arthur(MerlinToArthur, ArthurToMerlin, &wg)

	// Wait for both goroutines to finish
	wg.Wait()

	// Close the channels
	close(MerlinToArthur)
	close(ArthurToMerlin)

}
