/*-
 * ============LICENSE_START=======================================================
 * Author: Richard Masci
 * ================================================================================
 * Copyright (C) 2017 - 2020 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
