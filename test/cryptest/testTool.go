package main

import (
	"github.com/dterei/gotsc"
	"runtime"
	"sync"
	"syscall"
)

//type testTool func(func()) float64

var cycles []float64
var once sync.Once

func testMulty(index []int, concur, tps bool) ([]float64, string) {
	tool := singleTest
	if concur {
		tool = concurrentTest
	}

	ret := make([]float64, len(index))
	cycles = make([]float64, len(index))
	for i := range index {
		ret[i] = tool(algoList[index[i]])
		cycles[i] = ret[i]
		if tps {
			if concur {
				ret[i] = 1e9 / ret[i] * float64(algoInfoList[index[i]].modulus)
			} else {
				ret[i] = hz / ret[i] * float64(algoInfoList[index[i]].modulus)
			}
		} else {
			if concur {
				ret[i] = (ret[i] / 1e6) / float64(algoInfoList[index[i]].modulus) //ms
			} else {
				ret[i] = (ret[i] / 1000) / float64(algoInfoList[index[i]].modulus) //khz
			}
		}
	}
	if tps {
		return ret, "tps"
	}
	if concur && !tps {
		return ret, "ms"
	}
	return ret, "khz"
}

func concurrentTest(testCase func()) float64 {
	once.Do(func() {
		runtime.GOMAXPROCS(runtime.NumCPU())
	})

	job := totalJob / concurrent
	var group sync.WaitGroup
	group.Add(concurrent)
	start, end := new(syscall.Timeval), new(syscall.Timeval)
	_ = syscall.Gettimeofday(start)
	for i := 0; i < concurrent; i++ {
		go func() {
			for j := 0; j < job; j++ {
				testCase()
			}
			group.Done()
		}()
	}
	group.Wait()
	_ = syscall.Gettimeofday(end)
	avg := (float64(end.Nano() - start.Nano())) / float64(totalJob)
	return avg
}

func singleTest(testCase func()) float64 {
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()
	tsc := gotsc.TSCOverhead()
	start := gotsc.BenchStart()
	for i := 0; i < N; i++ {
		testCase()
	}
	end := gotsc.BenchEnd()
	avg := float64(end-start-tsc) / float64(N)
	return avg
}
