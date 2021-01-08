package main

import (
	"github.com/printzero/tint"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
)

//GetCPUInfoString GetCPUInfoString
func GetCPUInfoString() (ret string, hz float64) {
	defer func() {
		if e := recover(); e != nil {
			ret, hz = "", 0.0
		}
	}()
	cmdRelease := exec.Command("uname", "-v")
	cmdCPUInfo := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
	release, _ := cmdRelease.CombinedOutput()
	cpuInfo, _ := cmdCPUInfo.CombinedOutput()

	reg, _ := regexp.Compile(`@ *([0-9]+\.?[0-9]*)GHz`)
	loc := reg.FindSubmatch(cpuInfo)
	ghz := 0.0
	if len(loc) > 1 {
		ghz, _ = strconv.ParseFloat(string(loc[1]), 64)
	}
	hz = ghz * 1e9

	Magenta := t.SwatchRaw(tint.Magenta)
	Green := t.SwatchRaw(tint.Green)
	ret += Green("--------------------------Host Info Start-------------------------\n")
	ret += Magenta("OSName:\t\t" + runtime.GOOS + "\n")
	ret += Magenta("OSArch:\t\t" + runtime.GOARCH + "\n")
	if len(release) != 0 {
		ret += Magenta("OSRelease:\t" + string(release))
	}
	if len(cpuInfo) != 0 {
		ret += Magenta("CpuInfo:\t" + string(cpuInfo))
	}
	ret += Magenta("CPU:\t\t" + strconv.Itoa(runtime.NumCPU()) + "\n")
	ret += Magenta("MaxProc:\t" + strconv.Itoa(runtime.GOMAXPROCS(0)) + "\n")
	ret += Green("--------------------------Host Info End---------------------------\n")
	return
}
