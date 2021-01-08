package test

import (
	"fmt"
	"github.com/dterei/gotsc"
	"testing"
	"time"
)

func BenchmarkCounter_Performance(b *testing.B) {
	b.Run("gotsc 测试", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gotsc.BenchStart()
		}
	})
	b.Run("Counter 测试", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Counter()
		}
	})
	b.Run("Counter LFENCE 测试", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			CounterOrder()
		}
	})
	b.Run("Counter RDTSCP 测试", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			CounterRDTSCP()
		}
	})
}

func TestCounter_Accuracy(t *testing.T) {
	tsc := gotsc.TSCOverhead()
	fmt.Println("TSC 1 开销：", tsc)

	t.Run("测试gotsc包获得的数据", func(t *testing.T) {
		j := 0
		start := gotsc.BenchStart()
		for i := 0; i < 100000000; i++ {
			j++
		}
		end := gotsc.BenchEnd()
		fmt.Println("gotsc 数据 ：", end-start-tsc)
	})

	t.Run("测试Counter包获得的数据", func(t *testing.T) {
		j := 0
		start := Counter()
		for i := 0; i < 100000000; i++ {
			j++
		}
		end := Counter()
		fmt.Println("Counter 数据 ：", end-start-tsc)
	})

	t.Run("测试CounterLFENCE包获得的数据", func(t *testing.T) {
		j := 0
		start := CounterOrder()
		for i := 0; i < 100000000; i++ {
			j++
		}
		end := CounterOrder()
		fmt.Println("CounterLFENCE 数据 ：", end-start-tsc)
	})

	t.Run("测试CounterRDTSCP获得的数据", func(t *testing.T) {
		j := 0
		start := CounterRDTSCP()
		for i := 0; i < 100000000; i++ {
			j++
		}
		end := CounterRDTSCP()
		fmt.Println("CounterRDTSCP 数据 ：", end-start-tsc)
	})
	t.Run("time包测时间", func(t *testing.T) {
		j := 0
		now := time.Now()
		for i := 0; i < 100000000; i++ {
			j++
		}
		after := time.Since(now)
		fmt.Println("time测试获得的时间 ：", after.String())
	})
}

func TestCounter(t *testing.T) {
	c := Counter()
	fmt.Println("main counter :", c)
	go func() {
		c := Counter()
		fmt.Println("goroutine counter :", c)

	}()
	time.Sleep(1 * time.Second)
}

func TestName(t *testing.T) {
	for i := 0; i < 3; i++ {
		for j := 0; j < 2; j++ {
			fmt.Println("jjjj")
			break
		}
		fmt.Println("iiiii")
	}
	s := "abcd"
	s = s[0:2]
	fmt.Println(s)
}
