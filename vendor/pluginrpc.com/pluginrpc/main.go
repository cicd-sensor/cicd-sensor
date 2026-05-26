// Copyright 2024 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pluginrpc

import (
	"context"
	"os"
	"os/signal"
)

var interruptSignals = append(
	[]os.Signal{
		os.Interrupt,
	},
	extraInterruptSignals...,
)

// Main is a convenience function that will run the server within a main
// function with the proper semantics.
//
// All registration should already be complete before passing the Server to this function.
//
//	func main() {
//		pluginrpc.Main(newServer)
//	}
//
//	func newServer() (pluginrpc.Server, error) {
//		spec, err := examplev1pluginrpc.EchoServiceSpecBuilder{
//			EchoRequest: []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("echo", "request")},
//			EchoError:   []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("echo", "error")},
//		}.Build()
//		if err != nil {
//			return nil, err
//		}
//		serverRegistrar := pluginrpc.NewServerRegistrar()
//		echoServiceServer := examplev1pluginrpc.NewEchoServiceServer(pluginrpc.NewHandler(spec), echoServiceHandler{})
//		examplev1pluginrpc.RegisterEchoServiceServer(serverRegistrar, echoServiceServer)
//		return pluginrpc.NewServer(spec, serverRegistrar)
//	}
func Main(newServer func() (Server, error), _ ...MainOption) {
	ctx, cancel := withCancelInterruptSignal(context.Background())
	defer cancel()
	server, err := newServer()
	handleServerMainError(err)
	handleServerMainError(server.Serve(ctx, OSEnv))
}

// MainOption is an option for Main.
type MainOption func(*mainOptions)

// *** PRIVATE ***

func handleServerMainError(err error) {
	if err != nil {
		if errString := err.Error(); errString != "" {
			_, _ = os.Stderr.Write([]byte(errString + "\n"))
		}
		os.Exit(WrapExitError(err).ExitCode())
	}
}

// withCancelInterruptSignal returns a context that is cancelled if interrupt signals are sent.
func withCancelInterruptSignal(ctx context.Context) (context.Context, context.CancelFunc) {
	interruptSignalC, closer := newInterruptSignalChannel()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-interruptSignalC
		closer()
		cancel()
	}()
	return ctx, cancel
}

// newInterruptSignalChannel returns a new channel for interrupt signals.
//
// Call the returned function to cancel sending to this channel.
func newInterruptSignalChannel() (<-chan os.Signal, func()) {
	signalC := make(chan os.Signal, 1)
	signal.Notify(signalC, interruptSignals...)
	return signalC, func() {
		signal.Stop(signalC)
		close(signalC)
	}
}

type mainOptions struct{}
