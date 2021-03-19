package main

import (
	"github.com/spf13/pflag"
	"go.coder.com/cli"
)

type root struct{}

func (r *root) Run(fl *pflag.FlagSet) { fl.Usage() }

func (r *root) Spec() cli.CommandSpec {
	return cli.CommandSpec{
		Name:  "port-scanner",
		Usage: "[subcommand] [flags]",
		Desc:  "A simple port-scanner.",
	}
}

func (r *root) Subcommands() []cli.Command {
	return []cli.Command{
		new(scanCmd),
	}
}
