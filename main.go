package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"
)

const (
	DayInSeconds            = 86400
	DefaultDigitLength      = 6
	DefaultTimezoneLocation = "Europe/Istanbul"
)

var digitLength = flag.Int("d", DefaultDigitLength, "number of digits in the code")
var timezoneLocation = flag.String("tz", DefaultTimezoneLocation, "the timezone location you are in")

func generateDailyCode(secret string, digits int, timezoneLocation string) (string, time.Duration, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", 0, fmt.Errorf("invalid base32 secret: %v", err)
	}

	loc, err := time.LoadLocation(timezoneLocation)
	if err != nil {
		return "", 0, fmt.Errorf("invalid timezone: %v", err)
	}

	now := time.Now().In(loc)
	_, offset := now.Zone()
	shiftedNow := now.Unix() + int64(offset)
	counter := shiftedNow / DayInSeconds // wont expire in a day

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

	modulo := int(math.Pow10(digits))
	otp := binaryCode % modulo

	return fmt.Sprintf("%0*d", digits, otp), remaining, nil
}

func main() {
	flag.Parse()

	if *digitLength < 4 || *digitLength > 9 {
		log.Fatal("Error: digit length must be between 4 and 9")
	}

	secret, exists := os.LookupEnv("SECRET")
	if !exists || secret == "" {
		log.Fatal("Error: SECRET environment variable is not set")
	}

	code, remaining, err := generateDailyCode(secret, *digitLength, *timezoneLocation)
	if err != nil {
		log.Fatalf("Error generating OTP: %v", err)
	}

	fmt.Printf("Your code: %s\n", code)
	fmt.Printf("Valid for: %s\n", remaining.Round(time.Second))
}
