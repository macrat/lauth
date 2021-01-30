package api

import (
	"crypto/rand"
	"time"
)

func RandomDelay() {
	b := make([]byte, 1)
	rand.Read(b)
	time.Sleep(time.Duration(500+float64(b[0])*500/255) * time.Millisecond)
}
