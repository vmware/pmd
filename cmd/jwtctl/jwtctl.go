// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func main() {
	log.SetOutput(ioutil.Discard)
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("Version=%s\n", c.App.Version)
	}

	app := &cli.App{
		Name:    "jwtctl",
		Version: "v0.1",
		Usage:   "Emcode or Decode a JWT token",
	}

	app.EnableBashCompletion = true
	app.Commands = []*cli.Command{
		{
			Name:        "encode",
			Aliases:     []string{"s"},
			Usage:       "encode secret [SECRET] data [JSON DATA] alg [SIGNAlGORITHM [H256|H384|H512]]",
			Description: "Encode data using a secret",

			Action: func(c *cli.Context) error {
				encode(c.Args())
				return nil
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Failed to run cli: '%+v'", err)
	}
}
