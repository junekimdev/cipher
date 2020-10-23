package cipher

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/JuneKimDev/hash"
	"github.com/joho/godotenv"
)

func testSetup(t *testing.T) func() {
	t.Log("Set Up")
	err := godotenv.Load(".env")
	if err != nil {
		t.Errorf("Error loading .env file: %v\n", err)
	}
	return func() {
		t.Log("Tear Down")
	}
}

func TestGetCipherBlock(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	if _, err := getCipherBlock(); err != nil {
		t.Error("Failed to get cipher block")
	}
}

func TestGetCipherGCM(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	if _, err := getCipherGCM(); err != nil {
		t.Error("Failed to get cipher GCM")
	}
}

func TestGetIV(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	if _, err := getIV(16); err != nil {
		t.Error("Failed to get iv")
	}
}

func TestTextEncryptionFlow(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	expect := "test text"
	ciphertext, err := Encrypt(expect)
	if err != nil {
		t.Errorf("Failed to encpryt text: %v", err)
	}
	decryptedText, err := Decrypt(string(ciphertext))
	if err != nil {
		t.Errorf("Failed to decrypt text: %v", err)
	}

	if expect != string(decryptedText) {
		t.Errorf("Failed to verify encryption flow, got: %v, want: %v.", decryptedText, expect)
	}
}

func TestFileEncryptionFlow(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	plainText1 := "cipher_test_plain.txt"
	cipherText := "cipher_test_encrypt"
	plainText2 := "cipher_test_decrypt.txt"

	// create a file to test
	text := `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`
	if err := ioutil.WriteFile(plainText1, []byte(text), 0644); err != nil {
		log.Println("Failed to create a text file for the test")
	}

	// Encrypt and decrypt the file
	EncryptFile(plainText1, cipherText)
	DecryptFile(cipherText, plainText2)

	// Compare two files
	h1, _ := hash.RunFile(plainText1)
	h2, _ := hash.RunFile(plainText2)
	if h1 != h2 {
		t.Errorf("The two files are different: got: %v, want: %v", h1, h2)
	}
	defer os.Remove(plainText1)
	defer os.Remove(cipherText)
	defer os.Remove(plainText2)
}
