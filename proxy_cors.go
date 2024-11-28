/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Gin-Gonic
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.

 * This file may have been modified by CloudWeGo authors. All CloudWeGo
 * Modifications are Copyright 2024 CloudWeGo Authors.
 */

package cors

import (
	"bytes"
	"context"

	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/protocol"
)

func NewProxyCors(config Config) client.Middleware {
	cors := newCors(config)
	return func(e client.Endpoint) client.Endpoint {
		return func(ctx context.Context, req *protocol.Request, resp *protocol.Response) error {
			e(ctx, req, resp)
			cors.applyProxyCors(req, resp)
			return nil
		}
	}
}

func (cors *cors) handleProxyNormal(resp *protocol.Response) {
	for key, value := range cors.normalHeaders {
		if len(value) > 0 {
			resp.Header.Set(key, value)
		}
	}
}

func (cors *cors) applyProxyCors(req *protocol.Request, resp *protocol.Response) {
	origin := req.Header.Get("Origin")
	if len(origin) == 0 {
		return
	}
	host := req.Host()

	o := str2bytes(origin)
	if bytes.HasPrefix(o, DefaultSchemasBytes[0]) {
		if compareByteSlices(o, DefaultSchemasBytes[0], host) == 0 {
			return
		}
	}
	if bytes.HasPrefix(o, DefaultSchemasBytes[1]) {
		if compareByteSlices(o, DefaultSchemasBytes[1], host) == 0 {
			return
		}
	}

	if !cors.validateOrigin(origin) {
		return
	}

	cors.handleProxyNormal(resp)

	if !cors.allowAllOrigins {
		resp.Header.Set("Access-Control-Allow-Origin", origin)
	}
}
