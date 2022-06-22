// SPDX-License-Identifier: Apache-2.0

package hello

import (
	"net/http"

	"github.com/vmware/pmd/pkg/web"
)

// Hello JSON message
type Hello struct {
	Cmd  string `json:"cmd"`
	Text string `json:"text"`
}

// SayHello send message back whatever received
func (r *Hello) SayHello(rw http.ResponseWriter) error {
	g := Hello{
		Cmd:  r.Cmd,
		Text: r.Text,
	}

	return web.JSONResponse(g, rw)
}
