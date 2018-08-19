// a1 provides a CLI for obtaining a password hash which can then be included
// in an environment variable and used to configure an authenticated server
// for a single user.
package main

import (
	"fmt"
	"os"

	"github.com/scheibo/a1"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: a1 <PASSWORD>\n")
		os.Exit(1)
	}

	password := os.Args[1]
	hash, err := a1.Hash(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not hash %s: %s\n", password, err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", hash)
}
