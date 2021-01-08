package main

import (
	"fmt"
	"github.com/meshplus/flato-msp-cert/test"
	"github.com/printzero/tint"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

//N N
var N int
var algoList []func()
var algoInfoList []*testCase
var t = tint.Init()
var hz = 0.0
var cpuInfo = ""

func init() {
	algoList = []func(){
		test.SM2签名_hyperchain_sign_1,
		test.SM2验签_hyperchain_verify_1,
		test.SM3哈希_hyperchian_hash_1,
		test.SM4加密_hyperchian_enc_1,
		test.SM4解密_hyperchian_dec_1,
		test.SM2签名_tj_sign_1,
		test.SM2验签_tj_verify_1,
		test.ED25519签名_golang_sign_1,
		test.ED25519验签_golang_verify_1,
		test.ED25519签名_hyperchain_sign_1,
		test.ED25519验签_hyperchain_verify_1,
		test.P256k1验签_hyperchain_verify_1,
		test.P256k1验签_btcsuite_verify_1,
		test.P256k1签名_hyperchain_sign_1,
		test.P256k1签名_btcsuite_sign_1,
		test.P256r1签名_golang_sign_1,
		test.P256r1验签_golang_verify_1,
		test.ECC加密_hyperchain_enc_1,
		test.ECC解密_hyperchain_dec_1,

		test.Ed25519签名Witness_hyperchain_sign_1,
		test.Ed25519验签Part_hyperchain_verify_1,
		test.Ed25519签名Leader_hyperchain_sign_1,
		test.Ed25519验签Agg_hyperchain_verify_1,

		test.Ed25519签名batch64_hyperchain_sign_64,
		test.Ed25519验签batch64_hyperchain_verify_64,
		test.Ed25519签名batch1024_hyperchain_sign_1024,
		test.Ed25519验签batch1024_hyperchain_verify_1024,
	}

	rootCmd.AddCommand(singleCmd)
	singleCmd.Flags().IntVarP(&N, "n", "n", 1000,
		`Number of repetitions of password operations`)
	algoInfoList = make([]*testCase, len(algoList))
	for i := range algoList {
		algoInfoList[i] = getName(i)
	}
	cpuInfo, hz = GetCPUInfoString()
}

//rootCmd rootCmd
var rootCmd = &cobra.Command{
	Use:   "cryptest",
	Short: "a cli for test time efficiency of the crypto algo",
	Long:  `cryptest is a cli for test the time efficiency of the cryptographic algorithm`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(`
 ____  ____ ___  _ ____  _____  _____ ____  _____ 
/   _\/  __\\  \///  __\/__ __\/  __// ___\/__ __\
|  /  |  \/| \  / |  \/|  / \  |  \  |    \  / \  
|  \_ |    / / /  |  __/  | |  |  /_ \___ |  | |  
\____/\_/\_\/_/   \_/     \_/  \____\\____/  \_/  
                                                                   `)
		fmt.Println("welcome to cryptest:）")
		fmt.Println("------------------------")
		_ = cmd.Help()
		fmt.Println("------------------------")
		fmt.Println("2016-2020 (c) hyperchain co.,ltd.")
	},
}

var singleCmd = &cobra.Command{
	Use:   "run",
	Short: "test crypto algo",
	Long:  `test crypto algo`,
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
		var perfData string

		if _, err := exec.LookPath("perf"); err == nil {
			argsPerf := os.Args
			perfData = perfTest(argsPerf)
			regHz, _ := regexp.Compile(`#.*([0-9].\d{3}).*GHz`)
			byteHz := regHz.FindSubmatch([]byte(perfData))
			ghz, _ := strconv.ParseFloat(string(byteHz[1]), 64)
			hz = ghz * 1e9
		} else {
			reg, _ := regexp.Compile(`@ *([0-9]+\.?[0-9]*)GHz`)
			loc := reg.FindSubmatch([]byte(cpuInfo))
			ghz := 0.0
			if len(loc) > 1 {
				ghz, _ = strconv.ParseFloat(string(loc[1]), 64)
			}
			hz = ghz * 1e9
		}

		ret, u := testMulty(indexs, false, true)
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

func isNumber(s string) (int, bool) {
	i, err := strconv.ParseInt(s, 10, 64)
	return int(i), err == nil
}

type testCase struct {
	index   int
	allName string
	name    string
	author  string
	class   string
	modulus int64
}

func getName(i int) *testCase {
	s := runtime.FuncForPC(reflect.ValueOf(algoList[i]).Pointer()).Name()
	ss := strings.Split(s, ".")
	ret := new(testCase)
	ret.index = i
	ret.allName = ss[len(ss)-1]
	split := strings.Split(ret.allName, "_")
	ret.name = split[0]
	ret.author = split[1]
	ret.class = split[2]
	ret.modulus, _ = strconv.ParseInt(split[3], 10, 64)
	return ret
}

func main() {
	args := os.Args
	if len(args) > 1 {
		arg := strings.ToLower(args[1])
		index, isNum := isNumber(arg)
		if isNum {
			algoList[index]()
			return
		}
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func getIndexByClass(class string) (ret []int) {
	for i := range algoInfoList {
		if algoInfoList[i].class == class {
			ret = append(ret, i)
		}
	}
	return
}
