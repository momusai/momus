package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/momusai/momus/internal/mcp"
	"github.com/momusai/momus/internal/target"
)

type mcpOpts struct {
	url     string
	command string
	tool    string
	arg     string
	timeout time.Duration
}

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Audit and scan Model Context Protocol servers",
		Long: "MCP servers feed tool descriptions and tool output straight into a host\n" +
			"model's context, which makes both an injection surface the user never sees.\n\n" +
			"  momus mcp audit  — inspect what a server advertises, and flag injection\n" +
			"                     content in its own descriptions and resources\n" +
			"  momus mcp scan   — run the attack pack against one of its tools",
	}
	cmd.AddCommand(newMCPAuditCmd(), newMCPScanCmd())
	return cmd
}

// connect opens a client against whichever transport the flags describe.
//
// A stdio server is a program, and connecting to it means running that program.
// That is unavoidable — it is the only way to speak to one — but it is stated
// plainly here and in the command help rather than buried.
func (o *mcpOpts) connect(ctx context.Context) (*mcp.Client, error) {
	switch {
	case o.url != "" && o.command != "":
		return nil, fmt.Errorf("give either --url or --command, not both")
	case o.url != "":
		if !strings.HasPrefix(o.url, "http://") && !strings.HasPrefix(o.url, "https://") {
			return nil, fmt.Errorf("invalid --url %q (want http:// or https://)", o.url)
		}
		return mcp.New(mcp.NewHTTP(o.url, &http.Client{Timeout: o.timeout})), nil
	case o.command != "":
		parts := strings.Fields(o.command)
		if len(parts) == 0 {
			return nil, fmt.Errorf("--command is empty")
		}
		fmt.Fprintf(os.Stderr, "Running MCP server: %s\n", o.command)
		c := exec.CommandContext(ctx, parts[0], parts[1:]...) //nolint:gosec // the user named this server on purpose
		tr, err := mcp.NewStdioCmd(c)
		if err != nil {
			return nil, err
		}
		return mcp.New(tr), nil
	default:
		return nil, fmt.Errorf("specify the server: --url for an HTTP endpoint, or " +
			"--command to run a stdio server\n\n" +
			"examples:\n" +
			"  momus mcp audit --url https://mcp.example.com/mcp\n" +
			"  momus mcp audit --command \"npx -y @modelcontextprotocol/server-everything\"")
	}
}

func (o *mcpOpts) addFlags(c *cobra.Command) {
	c.Flags().StringVar(&o.url, "url", "", "MCP endpoint over streamable HTTP")
	c.Flags().StringVar(&o.command, "command", "", "command that runs a stdio MCP server (it will be executed)")
	c.Flags().DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
}

// ── audit ────────────────────────────────────────────────────────────────────

// suspicious matches phrasing that has no business in a tool description. A
// description is read by the host model as instructions, so an imperative aimed
// at the assistant is the payload in a tool-poisoning attack.
//
// These patterns are reported, never used to decide a verdict on their own: the
// output is a list for a human to read, which is why matching broadly is safe
// here in a way it would not be inside a detector.
var suspicious = []struct {
	name string
	re   *regexp.Regexp
}{
	{"instruction override", regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instruction|prompt|rule|direction)`)},
	{"addressed to the model", regexp.MustCompile(`(?i)\b(you are|you must|you should always|always respond|never mention|do not tell|don't tell)\b`)},
	{"hidden-instruction marker", regexp.MustCompile(`(?i)<\s*(system|important|secret|hidden)\s*>|\[\s*(system|important)\s*\]`)},
	{"exfiltration verb", regexp.MustCompile(`(?i)\b(send|post|upload|exfiltrate|transmit|forward)\b.{0,40}(https?://|\b(url|endpoint|webhook|api)\b)`)},
	{"credential interest", regexp.MustCompile(`(?i)\b(api[_ -]?key|secret|token|password|credential|\.env|ssh key)\b`)},
	{"tool-call steering", regexp.MustCompile(`(?i)\b(before (using|calling)|prior to (using|calling)|first call|always call)\b`)},
	{"concealment", regexp.MustCompile(`(?i)\b(do not (mention|reveal|disclose)|without (telling|informing)|silently)\b`)},
}

// invisible catches characters that render as nothing but are read by a model:
// zero-width spaces, joiners, bidi overrides, and the Unicode tag block used to
// smuggle ASCII invisibly.
var invisible = regexp.MustCompile(`[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}\x{E0000}-\x{E007F}]`)

func newMCPAuditCmd() *cobra.Command {
	var o mcpOpts
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect an MCP server's tools, prompts and resources for injection content",
		Long: "Lists everything a server advertises and flags text that reads as an\n" +
			"instruction to the host model rather than a description for a human.\n\n" +
			"A tool description is fed verbatim into the model's context, so it is an\n" +
			"injection vector the user never sees — and one that can change after\n" +
			"install, which is the \"rug pull\" pattern. Invisible Unicode is reported\n" +
			"too, since a description can carry text that renders as nothing.\n\n" +
			"With --command, the named program IS EXECUTED: that is the only way to\n" +
			"speak to a stdio server. Only audit servers you are willing to run.",
		Example: "  momus mcp audit --url https://mcp.example.com/mcp\n" +
			"  momus mcp audit --command \"npx -y @modelcontextprotocol/server-everything\"",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			return runMCPAudit(ctx, &o)
		},
	}
	o.addFlags(cmd)
	return cmd
}

type auditFinding struct {
	where  string // "tool read_file (description)"
	reason string
	sample string
}

func runMCPAudit(ctx context.Context, o *mcpOpts) error {
	c, err := o.connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()

	if err = c.Initialize(ctx); err != nil {
		return fmt.Errorf("could not complete the MCP handshake: %w", err)
	}
	fmt.Printf("Server:   %s %s\n", nonEmpty(c.ServerInfo.Name, "(unnamed)"), c.ServerInfo.Version)
	fmt.Printf("Protocol: %s\n", nonEmpty(c.Negotiated, "(unstated)"))
	if c.Negotiated != "" && c.Negotiated != mcp.ProtocolVersion {
		fmt.Printf("          note: this client speaks %s; the server chose a different revision\n", mcp.ProtocolVersion)
	}
	fmt.Println()

	var findings []auditFinding

	tools, err := c.ListTools(ctx)
	switch {
	case err != nil && mcp.IsMethodNotFound(err):
		fmt.Println("Tools:     none advertised")
	case err != nil:
		return fmt.Errorf("listing tools: %w", err)
	default:
		fmt.Printf("Tools (%d):\n", len(tools))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, t := range tools {
			fmt.Fprintf(w, "  %s\t%s\n", t.Name, firstLine(t.Description))
			findings = append(findings, inspect(fmt.Sprintf("tool %s (description)", t.Name), t.Description)...)
			findings = append(findings, inspect(fmt.Sprintf("tool %s (input schema)", t.Name), string(t.InputSchema))...)
		}
		_ = w.Flush()
	}
	fmt.Println()

	prompts, err := c.ListPrompts(ctx)
	switch {
	case err != nil && mcp.IsMethodNotFound(err):
		fmt.Println("Prompts:   not implemented by this server")
	case err != nil:
		fmt.Printf("Prompts:   could not list (%v)\n", err)
	default:
		fmt.Printf("Prompts (%d):\n", len(prompts))
		for _, p := range prompts {
			fmt.Printf("  %s  %s\n", p.Name, firstLine(p.Description))
			findings = append(findings, inspect(fmt.Sprintf("prompt %s (description)", p.Name), p.Description)...)
		}
	}
	fmt.Println()

	resources, err := c.ListResources(ctx)
	switch {
	case err != nil && mcp.IsMethodNotFound(err):
		fmt.Println("Resources: not implemented by this server")
	case err != nil:
		fmt.Printf("Resources: could not list (%v)\n", err)
	default:
		fmt.Printf("Resources (%d):\n", len(resources))
		for _, r := range resources {
			fmt.Printf("  %s  %s\n", r.URI, firstLine(r.Description))
			findings = append(findings, inspect(fmt.Sprintf("resource %s (description)", r.URI), r.Description)...)
		}
	}

	fmt.Println()
	if len(findings) == 0 {
		fmt.Println(color.GreenString("No injection-shaped content found in what this server advertises."))
		fmt.Println("That is not a clean bill of health: a server can still misbehave at call")
		fmt.Println("time. Use `momus mcp scan` to attack a tool directly.")
		return nil
	}

	fmt.Println(color.YellowString("%d item(s) worth a human's attention:", len(findings)))
	fmt.Println()
	for _, f := range findings {
		fmt.Printf("  %s\n", color.New(color.Bold).Sprint(f.where))
		fmt.Printf("    %s\n", f.reason)
		if f.sample != "" {
			fmt.Printf("    %s\n", color.HiBlackString("%s", f.sample))
		}
		fmt.Println()
	}
	fmt.Println("These are reported, not judged. A description legitimately about")
	fmt.Println("credentials will match too — read them and decide.")
	return nil
}

// inspect reports injection-shaped content in a piece of server-supplied text.
func inspect(where, text string) []auditFinding {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []auditFinding
	for _, s := range suspicious {
		if m := s.re.FindString(text); m != "" {
			out = append(out, auditFinding{where: where, reason: s.name, sample: excerpt(text, m)})
		}
	}
	if loc := invisible.FindStringIndex(text); loc != nil {
		out = append(out, auditFinding{
			where:  where,
			reason: "invisible Unicode (renders as nothing, but the model reads it)",
			sample: fmt.Sprintf("%d hidden character(s) at offset %d", len(invisible.FindAllString(text, -1)), loc[0]),
		})
	}
	return out
}

// excerpt shows the match with a little context around it.
func excerpt(text, match string) string {
	i := strings.Index(text, match)
	if i < 0 {
		return firstLine(match)
	}
	start, end := i-40, i+len(match)+40
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	s := strings.Join(strings.Fields(text[start:end]), " ")
	if start > 0 {
		s = "…" + s
	}
	if end < len(text) {
		s += "…"
	}
	return s
}

// nonEmpty returns s, or fallback when s is blank.
func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 88 {
		s = s[:88] + "…"
	}
	return s
}

// ── scan ─────────────────────────────────────────────────────────────────────

func newMCPScanCmd() *cobra.Command {
	var o mcpOpts
	scanO := &scanOpts{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run the attack pack against one of an MCP server's tools",
		Long: "Calls a tool repeatedly with the pack's payloads and scores what comes\n" +
			"back, exactly as a chat endpoint would be scanned.\n\n" +
			"What this tests: a tool whose output echoes attacker text verbatim is an\n" +
			"injection vector into whatever assistant is wired to it, because tool\n" +
			"output lands directly in the model's context.\n\n" +
			"If --arg is omitted it is inferred from the tool's input schema, and the\n" +
			"command stops rather than guessing when the choice is not obvious — a\n" +
			"payload delivered to the wrong parameter is never seen by the tool, and\n" +
			"would make it look perfectly safe.",
		Example: "  momus mcp scan --url https://mcp.example.com/mcp --tool search\n" +
			"  momus mcp scan --command \"npx -y server-everything\" --tool echo --arg message",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return scanO.validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			tgt, arg, cleanup, err := resolveMCPTarget(ctx, &o)
			if err != nil {
				return err
			}
			defer cleanup()

			label := o.url
			if label == "" {
				label = "mcp:" + o.command
			}
			// The liveness probe asks a model two benign questions and expects
			// different answers. A tool is not a model — a lookup tool answering
			// two queries identically is working correctly — so the probe would
			// reject healthy servers. The tool call itself already fails loudly
			// when the server is unreachable.
			scanO.skipProbe = true

			reflectionProbe(ctx, tgt, arg)
			fmt.Fprintln(os.Stderr)

			return runScanWith(ctx, tgt, label+" (tool "+o.tool+")", scanO)
		},
	}
	o.addFlags(cmd)
	scanO.addFlags(cmd)
	cmd.Flags().StringVar(&o.tool, "tool", "", "tool to attack (required)")
	cmd.Flags().StringVar(&o.arg, "arg", "", "tool argument to put the payload in (default: inferred)")
	return cmd
}

// resolveMCPTarget connects, picks the tool argument, and returns a scan target.
// It returns the resolved argument name too, so callers can report which
// parameter the payload actually went into rather than guessing.
func resolveMCPTarget(ctx context.Context, o *mcpOpts) (target.Target, string, func(), error) {
	c, err := o.connect(ctx)
	if err != nil {
		return nil, "", nil, err
	}
	cleanup := func() { _ = c.Close() }

	if err = c.Initialize(ctx); err != nil {
		cleanup()
		return nil, "", nil, fmt.Errorf("could not complete the MCP handshake: %w", err)
	}
	tools, err := c.ListTools(ctx)
	if err != nil {
		cleanup()
		return nil, "", nil, fmt.Errorf("listing tools: %w", err)
	}
	if o.tool == "" {
		cleanup()
		return nil, "", nil, fmt.Errorf("--tool is required; this server exposes: %s", toolNames(tools))
	}

	var chosen *mcp.Tool
	for i := range tools {
		if tools[i].Name == o.tool {
			chosen = &tools[i]
			break
		}
	}
	if chosen == nil {
		cleanup()
		return nil, "", nil, fmt.Errorf("no tool named %q; this server exposes: %s", o.tool, toolNames(tools))
	}

	arg := o.arg
	if arg == "" {
		arg = target.InferArg(chosen.InputSchema)
	}
	if arg == "" {
		cleanup()
		return nil, "", nil, fmt.Errorf("could not work out which argument of %q takes the payload — "+
			"pass --arg.\nGuessing would deliver every attack to a parameter the tool ignores, "+
			"and an untouched tool looks perfectly safe.\nits input schema: %s",
			o.tool, firstLine(string(chosen.InputSchema)))
	}
	fmt.Fprintf(os.Stderr, "MCP tool: %s (payload in %q)\n", o.tool, arg)
	return target.NewMCPTarget(c, o.tool, arg), arg, cleanup, nil
}

// reflectionProbe checks whether a tool returns caller-controlled text verbatim.
//
// This asks a different question from the attack pack, and MCP is why it has to
// exist. The pack asks "did the model obey the instruction?" — the right
// question for a chat endpoint, and the wrong one for a tool. A tool's output
// is pasted into the host model's context, so a tool that echoes its input is a
// path for attacker text to reach that model whether or not the tool itself
// "obeyed" anything. A search tool answering with the query prefixed by "No
// exact match:" scores as perfectly safe on every canary detector, and is still
// a conduit.
//
// The token is random, so a match cannot be chance. Reflection alone is not a
// vulnerability — plenty of tools echo for good reasons — so it is reported as
// something to reason about, with the condition that makes it matter stated.
func reflectionProbe(ctx context.Context, tgt target.Target, arg string) {
	var raw [9]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return
	}
	token := "MOMUS_REFLECT_" + strings.ToUpper(hex.EncodeToString(raw[:]))

	resp, err := tgt.Send(ctx, target.Request{Payload: token})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nReflection probe: could not run (%v)\n", err)
		return
	}
	if !strings.Contains(resp.Text, token) {
		fmt.Fprintf(os.Stderr, "\n%s this tool did not echo a random token back, so it is not\n"+
			"a direct path for caller text into the model's context.\n",
			color.GreenString("Reflection:"))
		return
	}

	fmt.Fprintf(os.Stderr, "\n%s this tool returned a random token verbatim in its output.\n",
		color.YellowString("Reflection: REFLECTS INPUT —"))
	fmt.Fprintf(os.Stderr, "  Tool output is inserted into the host model's context, so anything a\n"+
		"  caller can put in %q reaches that model as if the tool had said it.\n", arg)
	fmt.Fprintln(os.Stderr, "  That matters if untrusted input can reach this argument — a document,\n"+
		"  a web page, another tool's output, or a user message passed straight through.\n"+
		"  It is not a finding on its own: echoing a query back is often correct.")
}

func toolNames(tools []mcp.Tool) string {
	if len(tools) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return strings.Join(names, ", ")
}
