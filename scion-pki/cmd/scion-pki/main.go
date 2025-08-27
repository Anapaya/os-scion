// Copyright 2020 Anapaya Systems
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

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/certs"
	"github.com/scionproto/scion/scion-pki/key"
	"github.com/scionproto/scion/scion-pki/testcrypto"
	"github.com/scionproto/scion/scion-pki/trcs"
)

// CommandPather returns the path to a command.
type CommandPather interface {
	CommandPath() string
}

var (
	admonition = regexp.MustCompile(`:::(\w+)[^\n]*\n([\s\S]*?)\n:::\n`)
	codeBlock  = regexp.MustCompile("```[^\n]*\n([\\s\\S]*?)```")
)

func main() {
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:   executable,
		Short: "SCION Control Plane PKI Management Tool",
		Args:  cobra.NoArgs,
		// Silence the errors, since we print them in main. Otherwise, cobra
		// will print any non-nil errors returned by a RunE function.
		// See https://github.com/spf13/cobra/issues/340.
		// Commands should turn off the usage help message, if they deem the arguments
		// to be reasonable well-formed. This avoids outputing help message on errors
		// that are not caused by malformed input.
		// See https://github.com/spf13/cobra/issues/340#issuecomment-374617413.
		SilenceErrors: true,
	}
	defaultHelp := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		out := c.OutOrStdout()
		var buf bytes.Buffer
		c.SetOut(&buf)
		defaultHelp(c, nil)

		usage := buf.String()
		usage = codeBlock.ReplaceAllStringFunc(usage, func(capture string) string {
			matches := codeBlock.FindStringSubmatch(capture)
			lines := strings.Split(matches[1], "\n")
			var indentedLines []string
			for _, line := range lines {
				if strings.TrimSpace(line) == "" {
					// no indentation for empty lines
					indentedLines = append(indentedLines, "")
				} else {
					indentedLines = append(indentedLines, "    "+line)
				}
			}
			return strings.Join(indentedLines, "\n")
		})
		usage = admonition.ReplaceAllStringFunc(usage, func(capture string) string {
			matches := admonition.FindStringSubmatch(capture)
			lines := strings.Split(matches[2], "\n")
			var indentedLines []string
			for _, line := range lines {
				if strings.TrimSpace(line) == "" {
					// no indentation for empty lines
					indentedLines = append(indentedLines, "")
				} else {
					indentedLines = append(indentedLines, "    "+line)
				}
			}
			return matches[1] + ":\n" + strings.Join(indentedLines, "\n")
		})
		usage = strings.ReplaceAll(usage, "`<", "<")
		usage = strings.ReplaceAll(usage, ">`", ">")
		usage = strings.ReplaceAll(usage, "\\-", "-")
		c.SetOut(out)
		fmt.Fprint(c.OutOrStdout(), usage)
	})

	cmd.AddCommand(
		newVersion(),
		key.Cmd(cmd),
		certs.Cmd(cmd),
		trcs.Cmd(cmd),
		testcrypto.Cmd(cmd),
		command.NewGendocs(cmd),
		newKms(cmd),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		if code := app.ExitCode(err); code != -1 {
			os.Exit(code)
		}
		os.Exit(1)
	}
}
