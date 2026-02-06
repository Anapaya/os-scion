// Copyright 2023 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/scion-pki/key"
)

func newRequestCmd(pather command.Pather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		out      string
		trcFiles []string
		ca       []string
		remotes  []string

		timeout  time.Duration
		tracer   string
		logLevel string

		interactive bool
		noColor     bool
		refresh     bool
		noProbe     bool
		sequence    string
	}
	cmd := &cobra.Command{
		Use:   "request [flags] <csr-file> <chain-file> <key-file>",
		Short: "Request an AS certificate from a CA",
		Example: fmt.Sprintf(`  %[1]s request --trc ISD1-B1-S1.trc csr.pem cp-as.pem cp-as.key
  %[1]s request --trc ISD1-B1-S1.trc,ISD1-B1-S2.trc --out cp-as.new.pem csr.pem cp-as.pem cp-as.key
  %[1]s request --trc ISD1-B1-S1.trc --ca 1-ff00:0:110,1-ff00:0:111 csr.pem cp-as.pem cp-as.key
  %[1]s request --trc ISD1-B1-S1.trc --remote 1-ff00:0:110,172.30.200.2 csr.pem cp-as.pem cp-as.key
`, pather.CommandPath()),
		Long: `'request' requests an AS certificate from a remote CA using the provided CSR.

The provided ` + "`<chain-file>` `<key-file>` are used to sign the CSR provided in `<csr-file>`" + `.
They must be valid and verifiable by the remote CA in order for the request to be served.

By default, the target CA for the request is extracted from the certificate chain that
is used to sign the CSR. To select a different CA, you can specify the \--ca flag
with one or multiple target CAs. If multiple CAs are specified, they are tried
in the order that they are declared until the first successful certificate
chain renewal. If none of the declared CAs issued a verifiable certificate chain,
the command returns a non-zero exit code.

The TRCs are used to validate and verify the renewed certificate chain. If the
chain is not verifiable with any of the active TRCs the command returns a non-zero
exit code.

The resulting certificate chain is written to stdout by default. This can be changed
by specifying the \--out flag.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrFile := args[0]
			certFile := args[1]
			keyFile := args[2]
			printErr := func(f string, ctx ...interface{}) {
				fmt.Fprintf(cmd.ErrOrStderr(), f, ctx...)
			}
			printf := func(f string, ctx ...interface{}) {
				fmt.Fprintf(cmd.OutOrStdout(), f, ctx...)
			}

			if len(flags.ca) > 0 && len(flags.remotes) > 0 {
				return serrors.New("--ca and --remote must not both be set")
			}

			cmd.SilenceUsage = true

			// Set up observability tooling.
			if err := app.SetupLog(flags.logLevel); err != nil {
				return err
			}
			closer, err := setupTracer("scion-pki", flags.tracer)
			if err != nil {
				return serrors.Wrap("setting up tracing", err)
			}
			defer closer()

			span, ctx := tracing.CtxWith(cmd.Context(), "certificate.request")
			defer span.Finish()

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr, err := envFlags.Daemon()
			if err != nil {
				return serrors.WrapNoStack("resolving SCION environment", err)
			}
			localIP := net.IP(envFlags.Local().AsSlice())
			log.Debug("Resolved SCION environment flags",
				"daemon", daemonAddr,
				"local", localIP,
			)

			// Setup basic state.
			daemonCtx, daemonCancel := context.WithTimeout(ctx, time.Second)
			defer daemonCancel()
			sd, err := daemon.NewService(daemonAddr, daemon.Metrics{}).Connect(daemonCtx)
			if err != nil {
				return serrors.Wrap("connecting to SCION Daemon", err)
			}
			defer sd.Close()

			info, err := app.QueryASInfo(daemonCtx, sd)
			if err != nil {
				return err
			}
			span.SetTag("src.isd_as", info.IA)

			// Load cryptographic material
			trcs, err := loadTRCs(flags.trcFiles)
			if err != nil {
				return err
			}
			chain, err := loadChain(trcs, certFile)
			if err != nil {
				return serrors.Wrap("loading certificate chain", err)
			}
			priv, err := key.LoadPrivateKey("", keyFile)
			if err != nil {
				return serrors.Wrap("loading private key", err)
			}
			// Load CSR and create renewal request
			csr, err := loadCSR(csrFile)
			if err != nil {
				return serrors.Wrap("loading CSR", err)
			}
			req, err := createRenewalRequest(ctx, csr, priv, chain, trcs[0], info.IA)
			if err != nil {
				return serrors.Wrap("creating renewal request", err)
			}

			var cas []addr.IA
			var remotes []*snet.UDPAddr
			switch {
			case len(flags.ca) > 0:
				for _, raw := range flags.ca {
					ca, err := addr.ParseIA(raw)
					if err != nil {
						return serrors.Wrap("parsing CA", err)
					}
					cas = append(cas, ca)
				}
			case len(flags.remotes) > 0:
				for _, raw := range flags.remotes {
					addr, err := snet.ParseUDPAddr(raw)
					if err != nil {
						return serrors.Wrap("parsing remote", err)
					}
					remotes = append(remotes, addr)
				}
			default:
				ia, err := cppki.ExtractIA(chain[0].Issuer)
				if err != nil {
					panic(fmt.Sprintf("extracting ISD-AS from verified chain: %s", err))
				}
				printf("Extracted issuer from certificate chain: %s\n", ia)
				cas = []addr.IA{ia}
			}
			span.SetTag("ca-options", cas)
			span.SetTag("remote-options", remotes)

			r := renewer{
				LocalIA: info.IA,
				LocalIP: localIP,
				Daemon:  sd,
				Timeout: flags.timeout,
				StdErr:  cmd.ErrOrStderr(),
				PathOptions: func() []path.Option {
					pathOpts := []path.Option{
						path.WithInteractive(flags.interactive),
						path.WithRefresh(flags.refresh),
						path.WithSequence(flags.sequence),
						path.WithColorScheme(path.DefaultColorScheme(flags.noColor)),
					}
					if !flags.noProbe {
						pathOpts = append(pathOpts, path.WithProbing(&path.ProbeConfig{
							LocalIA: info.IA,
							LocalIP: localIP,
						}))
					}
					return pathOpts
				},
			}

			request := func(ca addr.IA, remote net.Addr) ([]*x509.Certificate, error) {
				printf("Attempt certificate renewal with %s\n", ca)
				span, ctx := tracing.CtxWith(ctx, "request")
				span.SetTag("dst.isd_as", ca)

				chain, err := r.Request(ctx, req, remote, ca)
				if err != nil {
					printErr("Sending request failed: %s\n", err)
					return nil, err
				}
				// Verify certificate chain
				verifyOptions := cppki.VerifyOptions{TRC: trcs}
				if verifyError := cppki.VerifyChain(chain, verifyOptions); verifyError != nil {
					printErr("Verification failed: %s\n", verifyError)
					// Output helpful info in case the TRC is in grace period.
					if maybeMissingTRCInGrace(trcs) {
						printErr(
							"Current time is still in Grace Period of latest TRC.\n"+
								"Try to verify with the predecessor TRC: "+
								"(Base = %d, Serial = %d)\n",
							trcs[0].ID.Base, trcs[0].ID.Serial-1,
						)
					}
					return nil, serrors.Wrap("verification failed", verifyError)
				}
				return chain, nil
			}

			var renewed []*x509.Certificate
			switch {
			case len(cas) > 0:
				for _, ca := range cas {
					remote := &snet.SVCAddr{SVC: addr.SvcCS}
					chain, err := request(ca, remote)
					if err != nil {
						continue
					}
					renewed = chain
					break
				}
			case len(remotes) > 0:
				for _, remote := range remotes {
					chain, err := request(remote.IA, remote)
					if err != nil {
						continue
					}
					renewed = chain
					break
				}
			}
			if renewed == nil {
				return serrors.New("failed to request certificate chain")
			}
			pemRenewed := encodeChain(renewed)
			if flags.out != "" {
				if err := os.WriteFile(flags.out, pemRenewed, 0644); err != nil {
					return serrors.Wrap("writing renewed certificate chain", err)
				}
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), string(pemRenewed))
			}
			return nil
		},
	}

	envFlags.Register(cmd.Flags())
	cmd.Flags().StringVar(&flags.out, "out", "",
		"The path to write the renewed certificate chain",
	)
	cmd.Flags().StringSliceVar(&flags.trcFiles, "trc", []string{},
		"Comma-separated list of trusted TRC files or glob patterns. "+
			"If more than two TRCs are specified,\n only up to two active TRCs "+
			"with the highest Base version are used (required)",
	)
	cmd.Flags().StringSliceVar(&flags.ca, "ca", nil,
		"Comma-separated list of ISD-AS identifiers of target CAs.\n"+
			"The CAs are tried in order until success or all of them failed.\n"+
			"--ca is mutually exclusive with --remote",
	)
	cmd.Flags().StringArrayVar(&flags.remotes, "remote", nil,
		"The remote CA address to use for certificate renewal.\n"+
			"The address is of the form <ISD-AS>,<IP>. --remote can be specified multiple times\n"+
			"and all specified remotes are tried in order until success or all of them failed.\n"+
			"--remote is mutually exclusive with --ca.",
	)
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 10*time.Second,
		"The timeout for the renewal request per CA",
	)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "",
		"The tracing agent address",
	)
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.sequence, "sequence", "", app.SequenceUsage)
	cmd.Flags().BoolVar(&flags.noProbe, "no-probe", false, "do not probe paths for health")
	cmd.Flags().BoolVar(&flags.refresh, "refresh", false, "set refresh flag for path request")

	cmd.MarkFlagRequired("trc")

	return cmd
}

func loadCSR(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, serrors.Wrap("reading CSR", err)
	}
	pemData, _ := pem.Decode(raw)
	if pemData != nil {
		raw = pemData.Bytes
	}
	if _, err := x509.ParseCertificateRequest(raw); err != nil {
		return nil, serrors.Wrap("parsing CSR", err)
	}
	return raw, nil
}
