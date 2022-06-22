// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"

	"github.com/pmd-nextgen/pkg/conf"
	"github.com/pmd-nextgen/pkg/validator"
)

type Response struct {
	Body       []byte
	Status     string
	StatusCode int
	Header     http.Header
}

type StatusResponse struct {
	Status string `json:"Status"`
	Link   string `json:"Link"`
}

type StatusDesc struct {
	Success bool           `json:"success"`
	Message StatusResponse `json:"message"`
	Errors  string         `json:"errors"`
}

const (
	defaultRequestTimeout = 5 * time.Second
)

func decodeHttpResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse body")
	}

	return body, nil
}

func buildHttpRequest(ctx context.Context, method string, url string, headers map[string]string, data interface{}) (*http.Request, error) {
	j := new(bytes.Buffer)
	if err := json.NewEncoder(j).Encode(data); err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, method, url, j)
	if err != nil {
		return nil, err
	}

	httpRequest.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpRequest.Header.Set(k, v)
	}

	return httpRequest, nil
}

func DispatchSocketWithStatus(method, host string, url string, headers map[string]string, data interface{}) (*Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	var httpClient *http.Client
	if validator.IsEmpty(host) {
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", conf.UnixDomainSocketPath)
				},
			},
		}
		url = "http://localhost" + url
	} else {
		if validator.IsVSockHost(host) {
			h := strings.Split(host, ":")
			cid, _ := strconv.ParseUint(h[0], 10, 32)
			port, _ := strconv.ParseUint(h[1], 10, 32)

			httpClient = &http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return vsock.Dial(uint32(cid), uint32(port))
					},
				},
			}
			url = "http://localhost" + url
		} else {
			httpClient = http.DefaultClient
			url = host + url
		}
	}

	req, err := buildHttpRequest(ctx, method, url, headers, data)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not complete HTTP request")
	}
	defer resp.Body.Close()

	var body []byte
	if resp.StatusCode == 200 {
		body, err = decodeHttpResponse(resp)
		if err != nil {
			return nil, err
		}
	}

	return &Response{
		Body:       body,
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
	}, nil
}

func DispatchSocket(method, host string, url string, headers map[string]string, data interface{}) ([]byte, error) {
	r, err := DispatchSocketWithStatus(method, host, url, headers, data)
	if err != nil {
		return nil, err
	}

	if r.StatusCode != 200 {
		return nil, errors.New(r.Status)
	}
	return r.Body, err
}

func DispatchAndWait(method, host string, url string, token map[string]string, data interface{}) ([]byte, error) {
	var msg []byte
	r, err := DispatchSocketWithStatus(method, host, url, token, data)
	if err != nil {
		return nil, err
	}
	if r.StatusCode == 202 {
		if location := r.Header.Get("Location"); location != "" {
			for {
				s, err := DispatchSocket(http.MethodGet, host, location, token, nil)
				if err != nil {
					fmt.Printf("retrieving job status failed: %v\n", err)
					return nil, err
				}
				status := StatusDesc{}
				err = json.Unmarshal(s, &status)
				if err != nil {
					fmt.Printf("Failed to decode json message: %v\n", err)
					return nil, err
				}
				if status.Message.Status == "complete" {
					link := status.Message.Link
					msg, err = DispatchSocket(http.MethodGet, host, link, token, nil)
					if err != nil {
						fmt.Printf("retrieving result failed: %v\n", err)
						return nil, err
					}
					break
				} else if status.Message.Status != "inprogress" {
					err = errors.New("unexptected status")
					return nil, err
				}
				time.Sleep(1 * time.Second)
				fmt.Printf(".")
			}
			fmt.Printf("\n")
		} else {
			err = errors.New("no location in headers")
			return nil, err
		}
	} else if r.StatusCode == 200 {
		msg = r.Body
	} else {
		return nil, err
	}
	return msg, err
}

func BuildAuthTokenFromEnv() (map[string]string, error) {
	token := os.Getenv("PHOTON_MGMT_AUTH_TOKEN")
	if token == "" {
		return nil, errors.New("authentication token not found")
	}

	headers := make(map[string]string)
	headers["X-Session-Token"] = token

	return headers, nil
}
