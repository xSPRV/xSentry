package console

import (
	"fmt"
	"io"
	"os"
)

const (
	reset  = "\033[0m"
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	dim    = "\033[2m"
)

var (
	output       io.Writer = os.Stderr
	colorEnabled bool
)

// Configure selects automatic, always-on, or disabled color output.
func Configure(mode string) error {
	switch mode {
	case "auto":
		colorEnabled = isTerminal(os.Stderr) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	case "always":
		colorEnabled = true
	case "never":
		colorEnabled = false
	default:
		return fmt.Errorf("invalid color mode %q (use auto, always, or never)", mode)
	}
	return nil
}

func Info(message string)     { write("•", cyan, message) }
func Progress(message string) { write("›", cyan, message) }
func Success(message string)  { write("✓", green, message) }
func Warning(message string)  { write("!", yellow, message) }
func Error(message string)    { write("✗", red, message) }

func Detail(label, value string) {
	if colorEnabled {
		fmt.Fprintf(output, "  %s%s:%s %s\n", dim, label, reset, value)
		return
	}
	fmt.Fprintf(output, "  %s: %s\n", label, value)
}

func write(symbol, color, message string) {
	if colorEnabled {
		fmt.Fprintf(output, "%s%s%s %s\n", color, symbol, reset, message)
		return
	}
	fmt.Fprintf(output, "%s %s\n", symbol, message)
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
