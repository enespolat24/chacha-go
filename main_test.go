package main

import (
	"encoding/hex"
	"testing"
)

func TestChaChaBlock(t *testing.T) {
	// Test vector (Key + Counter + Expected Keystream)
	state := []uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x01000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000001,
	}
	expectedKeystreamHex := "574b1ce6b106bb685a4456c7f8d520e61ca8f84489ef756f41b0086ef5d41c75f981accb771dfccd3dabb47bf23870872a08c18e119b178ad813e57b9622ee6b"

	stream, err := chachaBlock(state, 20)
	if err != nil {
		t.Errorf("Error generating block: %v", err)
		return
	}

	expectedKeystream, err := hex.DecodeString(expectedKeystreamHex)
	if err != nil {
		t.Fatalf("Failed to decode expected keystream: %v", err)
	}

	for i := 0; i < len(stream); i++ {
		if stream[i] != expectedKeystream[i] {
			t.Errorf("Keystream byte mismatch at index %d: got 0x%02x, want 0x%02x", i, stream[i], expectedKeystream[i])
		}
	}
}
