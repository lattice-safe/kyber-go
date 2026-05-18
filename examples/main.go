package main

import (
	"fmt"
	"log"

	"github.com/lattice-safe/kyber-go"
)

func main() {
	fmt.Println("=== ML-KEM / CRYSTALS-Kyber Example ===")
	
	// 1. Generate Key Pair (ML-KEM-768 / NIST Level 3)
	fmt.Println("Generating ML-KEM-768 key pair...")
	kp, err := kyber.GenerateKeyPair(kyber.Kyber768)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	defer kp.Zeroize() // Securely wipe the key pair from memory when done

	fmt.Printf("Public Key Size: %d bytes\n", len(kp.PublicKey()))
	fmt.Printf("Secret Key Size: %d bytes\n", len(kp.SecretKey()))

	// 2. Encapsulate (Sender side)
	fmt.Println("\nEncapsulating shared secret...")
	ct, ssEncaps, err := kyber.Encapsulate(kyber.Kyber768, kp.PublicKey())
	if err != nil {
		log.Fatalf("Failed to encapsulate: %v", err)
	}
	// Securely wipe the sender's copy of the shared secret after use
	defer kyber.Zeroize(ssEncaps)

	fmt.Printf("Ciphertext Size: %d bytes\n", len(ct))
	fmt.Printf("Sender's Shared Secret:   %x\n", ssEncaps)

	// 3. Decapsulate (Receiver side)
	fmt.Println("\nDecapsulating ciphertext...")
	ssDecaps, err := kp.Decapsulate(ct)
	if err != nil {
		log.Fatalf("Failed to decapsulate: %v", err)
	}
	// Securely wipe the receiver's copy of the shared secret after use
	defer kyber.Zeroize(ssDecaps)

	fmt.Printf("Receiver's Shared Secret: %x\n", ssDecaps)

	// 4. Verification
	if string(ssEncaps) == string(ssDecaps) {
		fmt.Println("\n✅ Success! Shared secrets match.")
	} else {
		fmt.Println("\n❌ Error! Shared secrets do not match.")
	}
}
