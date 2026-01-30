package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	StepSeconds = 86400
	DigitLength = 6
)

func generateTOTPpass(secret string) (string, time.Duration, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", 0, fmt.Errorf("invalid base32 secret: %v", err)
	}

	loc, _ := time.LoadLocation("Europe/Istanbul")
	now := time.Now().In(loc)

	_, offset := now.Zone()
	shiftedNow := now.Unix() + int64(offset)
	counter := shiftedNow / StepSeconds // wont expire in a day

	nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, loc)
	remaining := time.Until(nextMidnight)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha512.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	hmacOffset := sum[len(sum)-1] & 0xf

	binaryCode := (int(sum[hmacOffset])&0x7f)<<24 |
		(int(sum[hmacOffset+1])&0xff)<<16 |
		(int(sum[hmacOffset+2])&0xff)<<8 |
		(int(sum[hmacOffset+3]) & 0xff)

	otp := binaryCode % 1000000

	return fmt.Sprintf("%06d", otp), remaining, nil
}

func main() {
	secret, exists := os.LookupEnv("SECRET")
	if !exists || secret == "" {
		log.Fatal("Error: SECRET environment variable is not set")
	}

	otp, remaining, err := generateTOTPpass(secret)
	if err != nil {
		log.Fatalf("Error generating OTP: %v", err)
	}

	fmt.Printf("Your code: %s\n", otp)
	fmt.Printf("Valid for: %s\n", remaining.Round(time.Second))
}
