package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const banner = `
 ████████╗ █████╗ ███╗   ███╗██████╗ ███████╗██████╗ 
 ╚══██╔══╝██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔══██╗
    ██║   ███████║██╔████╔██║██████╔╝█████╗  ██████╔╝
    ██║   ██╔══██║██║╚██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║ ╚═╝ ██║██║     ███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

         by cipherKT  •  @cipherKT
         request manipulation testing tool
`

func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func printBanner() {
	clearScreen()
	fmt.Println(banner)
	fmt.Println(strings.Repeat("─", 58))
}
