//+build !amd64

package test

import "time"

//Counter nanotime
func Counter() uint64 {
	return uint64(time.Now().UnixNano())
}

//CounterOrder nanotime
func CounterOrder() uint64 {
	return uint64(time.Now().UnixNano())
}

//CounterRDTSCP nanotime
func CounterRDTSCP() uint64 {
	return uint64(time.Now().UnixNano())
}
