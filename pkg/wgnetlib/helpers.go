package gen

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image"
	"io"
	"net"

	"github.com/skip2/go-qrcode"
)

const (
	maxQRCodeSize = 2953
	qrImgSize     = 256
)

func GetQR(s string) (image.Image, error) {
	var img image.Image

	if len(s) > maxQRCodeSize {
		return img, nil
	}

	// Generate a QR code from the file contents
	qrCode, err := qrcode.New(s, qrcode.Medium)
	if err != nil {
		return img, fmt.Errorf("qr code error: %w", err)
	}

	return qrCode.Image(qrImgSize), nil
}

func GeneratePreSharedKey() string {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(key)
}

func EstimateNetworkSize(ipNet *net.IPNet) int {
	prefixSize, _ := ipNet.Mask.Size()

	// for IPv4
	if ipNet.IP.To4() != nil {
		return 1 << (32 - prefixSize)
	}

	// for IPv6
	return 1 << (128 - prefixSize)
}

func NextIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] > 0 {
			break
		}
	}

	return newIP
}

// GzipString compresses a string using gzip and returns it as a string..
func GzipString(s string) (string, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)

	_, err := w.Write([]byte(s))
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GunzipString decompresses a string using gzip and returns it as a string.
func GunzipString(s string) (string, error) {
	r, err := gzip.NewReader(bytes.NewReader([]byte(s)))
	if err != nil {
		return "", err
	}

	res, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(res), nil
}
