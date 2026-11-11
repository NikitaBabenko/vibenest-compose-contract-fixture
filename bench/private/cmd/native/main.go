package main

import (
	"flag"
	"fmt"
	"os"
	fixture "vibenest.invalid/disposable/privatefixture"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(64)
	}
	var err error
	switch os.Args[1] {
	case "broker":
		f := flag.NewFlagSet("broker", flag.ContinueOnError)
		helper := f.String("helper", "", "")
		ip := f.String("ip", "", "")
		if f.Parse(os.Args[2:]) != nil {
			os.Exit(64)
		}
		err = fixture.RunBroker(*helper, *ip, os.Stdin, os.Stdout)
	case "helper":
		f := flag.NewFlagSet("helper", flag.ContinueOnError)
		phase := f.String("phase", "", "")
		origin := f.String("origin", "", "")
		projectDirectory := f.String("project-directory", ".", "")
		if f.Parse(os.Args[2:]) != nil {
			os.Exit(64)
		}
		if *projectDirectory != "." {
			os.Exit(64)
		}
		err = fixture.RunHelper(*phase, *origin)
	default:
		os.Exit(64)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Private fixture refused")
		os.Exit(65)
	}
}
