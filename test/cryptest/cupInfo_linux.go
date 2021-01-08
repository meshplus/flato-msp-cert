package main

import (
	"github.com/printzero/tint"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

//GetCPUInfoString GetCPUInfoString
func GetCPUInfoString() (ret string, hz float64) {
	defer func() {
		if e := recover(); e != nil {
			ret, hz = "", 0.0
		}
	}()
	cmdRelease := exec.Command("uname", "-v")
	cmdCPUInfo := exec.Command("less", "/proc/cpuinfo")
	release, _ := cmdRelease.CombinedOutput()
	cpuInfoByte, _ := cmdCPUInfo.CombinedOutput()
	var cpuInfoInner string
	reg, _ := regexp.Compile(`model name.*GHz`)
	//regHz, _ := regexp.Compile(`@ *([0-9]+\.?[0-9]*)GHz`)
	//ghz := 0.0
	if reg.MatchString(string(cpuInfoByte)) {
		cpuInfotmp := reg.FindString(string(cpuInfoByte))
		index := strings.Index(cpuInfotmp, ":")
		cpuInfoInner = cpuInfotmp[index+2:]
		//hzTmp := regHz.FindSubmatch([]byte(cpuInfoInner))
		//ghz, _ = strconv.ParseFloat(string(hzTmp[1]), 64)
	}
	//hz = ghz * 1e9

	Magenta := t.SwatchRaw(tint.Magenta)
	Green := t.SwatchRaw(tint.Green)
	ret += Green("--------------------Host Info Start-------------------\n")
	ret += Magenta("OSName:\t\t" + runtime.GOOS + "\n")
	ret += Magenta("OSArch:\t\t" + runtime.GOARCH + "\n")
	if len(release) != 0 {
		ret += Magenta("OSRelease:\t" + string(release))
	}
	if len(cpuInfoInner) != 0 {
		ret += Magenta("CpuInfo:\t" + cpuInfoInner + "\n")
	}
	ret += Magenta("CPU:\t\t" + strconv.Itoa(runtime.NumCPU()) + "\n")
	ret += Magenta("processor:\t" + strconv.Itoa(runtime.GOMAXPROCS(0)) + "\n")
	ret += Green("--------------------Host Info End-------------------\n")
	return
}
