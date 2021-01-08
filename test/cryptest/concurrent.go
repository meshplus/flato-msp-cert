package main

import (
	"fmt"
	"github.com/printzero/tint"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var concurrent int
var totalJob int

func init() {
	rootCmd.AddCommand(concurrentCmd)
	concurrentCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 100,
		"Concurrency of testing，number of go routines")
	concurrentCmd.Flags().IntVarP(&totalJob, "n", "n", 10000,
		`Number of repetitions of password operations`)
	rootCmd.AddCommand(perfCmd)
	perfCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 100,
		"Concurrency of testing，number of go routines")
	perfCmd.Flags().IntVarP(&totalJob, "n", "n", 10000,
		`Number of repetitions of password operations`)
}

var concurrentCmd = &cobra.Command{
	Use:   "concur",
	Short: "concurrent test crypto algo",
	Long:  `concurrent crypto algo`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(cpuInfo)
		if len(args) < 1 {
			fmt.Println(`Please specify the algo to be tested, support：sign、verify、enc、dec、hash, or number:`)
			for i := range algoList {
				j := getName(i)
				fmt.Printf("%2d, name: %-20v, author: %-12v, class: %-5v\n", j.index, j.name, j.author, j.class)
			}
			return
		}
		arg := strings.ToLower(args[0])
		index, isNum := isNumber(arg)
		max := 0.0
		var indexs []int
		switch {
		case isNum:
			indexs = []int{index}
		case arg == "sign" || arg == "verify" || arg == "enc" || arg == "dec" || arg == "hash":
			indexs = getIndexByClass(arg)
		default:
			return
		}

		fmt.Printf("Core: %v, Concurrency: %v, N: %v\n", runtime.NumCPU(), concurrent, totalJob)
		ret, u := testMulty(indexs, true, true)

		for _, selected := range ret {
			if selected > max {
				max = selected
			}
		}
		for i, selected := range indexs {
			fmt.Printf("name:%-28s | author:%-20s | %-25s | %15s%% | cycles:%-20s\n",
				t.Raw(algoInfoList[selected].name, tint.Green),
				t.Raw(algoInfoList[selected].author, tint.Green),
				t.Raw(strconv.FormatFloat(ret[i], 'f', 3, 64)+u, tint.Green),
				t.Raw(strconv.FormatFloat(ret[i]/max*100, 'f', 1, 64), tint.Green),
				t.Raw(strconv.FormatFloat(cycles[i], 'f', 3, 64), tint.Green),
			)
		}
	},
}

var perfCmd = &cobra.Command{
	Use:   "perf",
	Short: "perf test crypto algo",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println(`Please specify the algo to be tested, support number:`)
			for i := range algoList {
				j := getName(i)
				fmt.Printf("%2d, name: %-20v, author: %-12v, class: %-5v\n", j.index, j.name, j.author, j.class)
			}
			return
		}
		appArg := os.Args
		commandPerf := exec.Command("perf", "stat", appArg[0], appArg[2])
		ret, _ := commandPerf.CombinedOutput()
		arg := strings.ToLower(appArg[2])
		index, _ := isNumber(arg)
		fmt.Println(t.Raw("--------------------Perf stat test--------------------", tint.Green))
		fmt.Printf("                 %s", t.Raw("Test case : ", tint.Green))
		fmt.Printf("%s\n", t.Raw(algoInfoList[index].name, tint.Green))
		fmt.Println(string(ret))
	},
}

func perfTest(args []string) string {
	for len(args) < 1 {
		return ""
	}
	commandPerf := &exec.Cmd{
		Path: "perf",
		Args: append([]string{"perf"}, "stat"),
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "concur" || args[i] == "run" {
			commandPerf.Args = append(commandPerf.Args, "perf")
		}
		commandPerf.Args = append(commandPerf.Args, args[i])

	}
	if filepath.Base("perf") == "perf" {
		if lp, err := exec.LookPath("perf"); err == nil {
			commandPerf.Path = lp
		}
	}
	ret, _ := commandPerf.CombinedOutput()

	return string(ret)
}
