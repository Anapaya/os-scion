// Copyright 2023 Anapaya Systems

package command

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

type regexpReplacer struct {
	Search  *regexp.Regexp
	Replace string
}

//go:embed sidebar.ts.tmpl
var sbTmpl string

var sidebarTemplate = template.Must(template.New("sidebar").Funcs(template.FuncMap{
	"replace":  strings.ReplaceAll,
	"basename": filepath.Base,
}).Parse(sbTmpl))

var headers = []regexpReplacer{
	{Search: regexp.MustCompile("\n## "), Replace: "\n# "},
	{Search: regexp.MustCompile("\n### "), Replace: "\n## "},
	{Search: regexp.MustCompile("\n#### "), Replace: "\n### "},
	{Search: regexp.MustCompile("\n##### "), Replace: "\n#### "},
}

var mystReplacers = []regexpReplacer{
	{Search: regexp.MustCompile(`:::(\w+)[^\n]*\n`), Replace: ":::{$1}\n"},
}

var docusaurusReplacers = []regexpReplacer{}

const (
	styleMyst       = "myst"
	styleDocusaurus = "docusaurus"
)

type sidebarItem struct {
	ID       string
	Children []sidebarItem
}

type input struct {
	BasePath string
	Items    []sidebarItem
}

func NewGendocs(pather Pather) *cobra.Command {
	var style string
	var sidebarBasePath string
	cmd := &cobra.Command{
		Use:    "gendocs <directory>",
		Short:  "Generate documentation",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().DisableAutoGenTag = true

			directory := args[0]
			if err := os.MkdirAll(directory, 0o755); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
			sb, err := genMarkdownTree(cmd.Root(), directory, style)
			if err != nil {
				return fmt.Errorf("generating documentation: %w", err)
			}
			if sidebarBasePath != "" {
				var b bytes.Buffer
				err := sidebarTemplate.Funcs(template.FuncMap{
					"replace": strings.ReplaceAll,
				}).Execute(&b, input{
					BasePath: sidebarBasePath,
					Items:    []sidebarItem{sb},
				})
				if err != nil {
					return fmt.Errorf("generating sidebar.ts: %w", err)
				}
				if err := os.WriteFile(path.Join(directory, "sidebar.ts"), b.Bytes(), 0o666); err != nil {
					return fmt.Errorf("writing sidebar.ts: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().
		StringVar(&style, "style", styleMyst, fmt.Sprintf("The style to use for the documentation. Options: %s, %s", styleMyst, styleDocusaurus))
	cmd.Flags().
		StringVar(&sidebarBasePath, "sidebar_base_path", "", "The base path for the sidebar items. If set, a sidebar.ts will be generated in the specified directory.")
	return cmd
}

func genMarkdownTree(cmd *cobra.Command, dir string, style string) (sidebarItem, error) {
	var children []string
	sidebar := sidebarItem{
		ID: strings.ReplaceAll(cmd.CommandPath(), " ", "_"),
	}
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		csb, err := genMarkdownTree(c, dir, style)
		if err != nil {
			return sidebarItem{}, err
		}
		sidebar.Children = append(sidebar.Children, csb)
		children = append(children, strings.ReplaceAll(c.CommandPath(), " ", "_"))
	}

	var buf bytes.Buffer
	if _, err := buf.WriteString("---\norphan: true\n---\n\n"); err != nil {
		return sidebarItem{}, err
	}
	if err := doc.GenMarkdown(cmd, &buf); err != nil {
		return sidebarItem{}, err
	}

	// Create index.
	if style == styleMyst && len(children) != 0 {
		if _, err := buf.WriteString("```{toctree}\n---\nhidden: true\n---\n"); err != nil {
			return sidebarItem{}, err
		}
		if _, err := buf.WriteString(strings.Join(children, "\n")); err != nil {
			return sidebarItem{}, err
		}
		if _, err := buf.WriteString("\n```\n"); err != nil {
			return sidebarItem{}, err
		}
	}

	// Replace titles
	raw := buf.Bytes()
	for _, h := range headers {
		raw = h.Search.ReplaceAll(raw, []byte(h.Replace))
	}
	switch style {
	case styleMyst:
		for _, mystReplace := range mystReplacers {
			raw = mystReplace.Search.ReplaceAll(raw, []byte(mystReplace.Replace))
		}
	case styleDocusaurus:
		for _, docusaurusReplace := range docusaurusReplacers {
			raw = docusaurusReplace.Search.ReplaceAll(raw, []byte(docusaurusReplace.Replace))
		}
	}

	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
	return sidebar, os.WriteFile(filepath.Join(dir, basename), raw, 0o666)
}
