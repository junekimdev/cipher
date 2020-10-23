package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

// Error
var (
	ErrEnvNotLoaded = errors.New("Environment variables are not loaded")
)

func getCipherBlock() (cipher.Block, error) {
	st := os.Getenv("CIPHER_SALT")
	pw := os.Getenv("CIPHER_PASSWORD")
	if st == "" || pw == "" {
		return nil, ErrEnvNotLoaded
	}

	salt := []byte(st)
	password := []byte(pw)

	// The recommended parameters are N=32768, r=8 and p=1 (as of 2017)
	key, err := scrypt.Key(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return aes.NewCipher(key)
}

func getCipherGCM() (cipher.AEAD, error) {
	block, err := getCipherBlock()
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func getIV(size int) ([]byte, error) {
	// Change password/salt pair when more than 2^32 IV nonces are generated
	// because of the risk of a repeat
	iv := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Printf("Failed to get iv: %v", err)
		return nil, err
	}
	return iv, nil
}

// Encrypt plaintext with GCM cipher
func Encrypt(text string) ([]byte, error) {
	plaintext := []byte(text)

	gcm, err := getCipherGCM()
	if err != nil {
		return nil, err
	}

	iv, err := getIV(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(iv, iv, plaintext, nil)
	return ciphertext, nil
}

// Decrypt encrypted text with GCM cipher
func Decrypt(encrypted string) ([]byte, error) {

	ciphertext := []byte(encrypted)

	gcm, err := getCipherGCM()
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, iv, ciphertext, nil)
}

// EncryptFile encrypts a file with CTR cipher
func EncryptFile(inFilepath, outFilepath string) error {
	infile, err := os.Open(inFilepath)
	if err != nil {
		return err
	}
	defer infile.Close()

	outfile, err := os.OpenFile(outFilepath, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	defer outfile.Close()

	block, err := getCipherBlock()
	if err != nil {
		return err
	}

	iv, err := getIV(block.BlockSize())
	if err != nil {
		return err
	}

	// To encrypt stream, Cipher CTR mode is used
	stream := cipher.NewCTR(block, iv)
	if err != nil {
		return err
	}

	// The buffer size must be multiple of 16 bytes
	buf := make([]byte, 16*64)

	// Loop until the EOF
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalf("Read %d bytes: %v", n, err)
			return err
		}
	}
	// Append the IV at the EOF
	outfile.Write(iv)
	return nil
}

// DecryptFile decrypts an encrypted file with CTR cipher
func DecryptFile(inFilepath, outFilepath string) error {
	infile, err := os.Open(inFilepath)
	if err != nil {
		return err
	}
	defer infile.Close()

	outfile, err := os.OpenFile(outFilepath, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	defer outfile.Close()

	fileinfo, err := infile.Stat()
	if err != nil {
		return err
	}

	block, err := getCipherBlock()
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	msgLen := fileinfo.Size() - int64(len(iv))
	_, err = infile.ReadAt(iv, msgLen)
	if err != nil {
		return err
	}

	// To decrypt stream, Cipher CTR mode is used
	stream := cipher.NewCTR(block, iv)
	if err != nil {
		return err
	}

	// The buffer size must be multiple of 16 bytes
	buf := make([]byte, 16*64)

	// Loop until the EOF
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			// The last bytes are the IV
			// Exclude them to get the original message portion
			if n > int(msgLen) {
				n = int(msgLen)
			}
			msgLen -= int64(n)

			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalf("Read %d bytes: %v", n, err)
			return err
		}
	}
	return nil
}
