// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package web

import (
	"encoding/json"
	"net/http"
)

type JSONResponseMessage struct {
	Success bool        `json:"success"`
	Message interface{} `json:"message"`
	Errors  string      `json:"errors"`
}

func httpResponse(m *JSONResponseMessage, w http.ResponseWriter) error {
	j, err := json.Marshal(m)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)

	return nil
}

func JSONResponse(response interface{}, w http.ResponseWriter) error {
	m := JSONResponseMessage{
		Success: true,
		Message: response,
	}

	return httpResponse(&m, w)
}

func JSONResponseError(err error, w http.ResponseWriter) error {
	m := JSONResponseMessage{
		Success: false,
		Errors:  err.Error(),
	}

	return httpResponse(&m, w)
}

func JSONUnmarshal(msg []byte) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	if err := json.Unmarshal(msg, &m); err != nil {
		return nil, err
	}
	return m, nil
}
