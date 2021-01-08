package test

//Counter use rdtsc, please use it
func Counter() uint64

//CounterOrder use lfence for out of order
func CounterOrder() uint64

//CounterRDTSCP use rdtscp
func CounterRDTSCP() uint64
