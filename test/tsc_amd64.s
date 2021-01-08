#include "textflag.h"

// func Counter() uint64
TEXT ·Counter(SB),NOSPLIT,$0-8
	RDTSC
	SHLQ	$32, DX
	ADDQ	DX, AX
	MOVQ	AX, ret+0(FP)
	RET

//func CounterOrder() uint64
TEXT ·CounterOrder(SB),NOSPLIT,$0-8
	LFENCE
	RDTSC
	SHLQ	$32, DX
	ADDQ	DX, AX
	MOVQ	AX, ret+0(FP)
	RET

//func CounterRDTSCP() uint64
TEXT ·CounterRDTSCP(SB),NOSPLIT,$0-8
	BYTE	$0x0F // RDTSCP
    BYTE	$0x01
    BYTE	$0xF9
	SHLQ	$32, DX
	ADDQ	DX, AX
	MOVQ	AX, ret+0(FP)
	RET
