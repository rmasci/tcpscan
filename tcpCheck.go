/*-
 * ============LICENSE_START=======================================================
 * Author: Richard Masci
 * ================================================================================
 * Copyright (C) 2017 - 2020 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
 * The MIT License (MIT)
 *
 * Copyright <year> AT&T Intellectual Property. All other rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ============LICENSE_END=========================================================
 */

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tevino/tcp-shaker"
)

func tcpChecker(hostport string, timeout time.Duration) string {
	c := tcp.NewChecker()
	var fp, op, cp string
	ctx, stopChecker := context.WithCancel(context.Background())
	defer stopChecker()
	go func() {
		if err := c.CheckingLoop(ctx); err != nil {
			fmt.Println("checking loop stopped due to fatal error: ", err)
		}
	}()

	<-c.WaitReady()
	if verb {
		fp = filterPort + "."
		op = openPort + "."
		cp = closedPort + "."
	} else {
		fp = filterPort
		op = openPort
		cp = closedPort
	}
	//timeout := time.Second * 1
	err := c.CheckAddr(hostport, timeout)
	switch err {
	case tcp.ErrTimeout:
		return fp
	case nil:
		return op
	default:
		return cp
	}
}
