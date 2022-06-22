// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/pmd-nextgen/pkg/validator"
	"github.com/urfave/cli/v2"
)

func encode(args cli.Args) {
	argStrings := args.Slice()

	var data string
	var secret string
	var signMethod string
	for i := range argStrings {
		switch argStrings[i] {
		case "secret":
			secret = argStrings[i+1]
		case "data":
			data = argStrings[i+1]
		case "alg":
			signMethod = argStrings[i+1]
		}
	}

	if validator.IsEmpty(secret) {
		secret = os.Getenv("JWT_SECRET")
	}

	if validator.IsEmpty(secret) || validator.IsEmpty(data) {
		fmt.Printf("Missing secret or JSON data \n")
		return
	}

	var dataJSON map[string]interface{}
	if err := json.Unmarshal([]byte(data), &dataJSON); err != nil {
		fmt.Errorf("Could not unmarshal the JSON data: %v", err)
		return
	}

	var signAlgorithm *jwt.SigningMethodHMAC
	switch signMethod {
	case "H256":
		signAlgorithm = jwt.SigningMethodHS256
	case "H384":
		signAlgorithm = jwt.SigningMethodHS384
	case "H512":
		signAlgorithm = jwt.SigningMethodHS512
	default:
		signAlgorithm = jwt.SigningMethodHS256
	}

	if t, ok := dataJSON["exp"]; ok {
		dataJSON["exp"] = t
	} else {
		dataJSON["exp"] = time.Now().Add(5 * 24 * time.Hour).Unix()
	}

	if t, ok := dataJSON["iat"]; ok {
		dataJSON["iat"] = t
	} else {
		dataJSON["iat"] = time.Now().Unix()
	}

	claim := jwt.NewWithClaims(
		signAlgorithm, jwt.MapClaims(
			dataJSON,
		),
	)

	token, err := claim.SignedString([]byte(secret))
	if err != nil {
		fmt.Printf("Failed to write token \n")
		return
	}

	fmt.Printf("%s\n", token)
}
