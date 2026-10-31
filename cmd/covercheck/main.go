// Command covercheck rejects a PR whose statement coverage is below its base.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"regexp"
	"strconv"
)

type coverage struct{ covered, total uint64 }

func (c coverage) ratio() *big.Rat {
	return new(big.Rat).SetFrac(new(big.Int).SetUint64(c.covered), new(big.Int).SetUint64(c.total))
}

func (c coverage) percent() string {
	return new(big.Rat).Mul(c.ratio(), big.NewRat(100, 1)).FloatString(6) + "%"
}

var profileLine = regexp.MustCompile(`^(.+:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+) ([0-9]+) ([0-9]+)$`)

// A block can appear in several test binaries when -coverpkg=./... is used.
// Count its statements once, and consider it covered if any binary hit it.
func readCoverage(r io.Reader) (coverage, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return coverage{}, errors.New("missing coverage mode header")
	}
	switch scanner.Text() {
	case "mode: set", "mode: count", "mode: atomic":
	default:
		return coverage{}, errors.New("invalid coverage mode")
	}
	type block struct {
		statements uint64
		hit        bool
	}
	blocks := make(map[string]block)
	line := 1
	for scanner.Scan() {
		line++
		fields := profileLine.FindStringSubmatch(scanner.Text())
		if fields == nil {
			return coverage{}, fmt.Errorf("invalid coverage record at line %d", line)
		}
		statements, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return coverage{}, fmt.Errorf("invalid statement count at line %d", line)
		}
		count, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return coverage{}, fmt.Errorf("invalid execution count at line %d", line)
		}
		previous, exists := blocks[fields[1]]
		if exists && previous.statements != statements {
			return coverage{}, fmt.Errorf("inconsistent duplicate block at line %d", line)
		}
		blocks[fields[1]] = block{statements: statements, hit: previous.hit || count > 0}
	}
	if err := scanner.Err(); err != nil {
		return coverage{}, fmt.Errorf("read coverage: %w", err)
	}
	var result coverage
	for _, b := range blocks {
		if b.statements > math.MaxUint64-result.total {
			return coverage{}, errors.New("statement total overflow")
		}
		result.total += b.statements
		if b.hit {
			result.covered += b.statements
		}
	}
	if result.total == 0 {
		return coverage{}, errors.New("coverage profile contains no statements")
	}
	return result, nil
}

func loadCoverage(path string) (coverage, error) {
	file, err := os.Open(path)
	if err != nil {
		return coverage{}, err
	}
	defer file.Close()
	return readCoverage(file)
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("covercheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	basePath := flags.String("base", "", "Target-branch coverage profile")
	headPath := flags.String("head", "", "PR coverage profile")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *basePath == "" || *headPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: covercheck -base base.out -head head.out")
		return 2
	}
	base, err := loadCoverage(*basePath)
	if err != nil {
		fmt.Fprintf(stderr, "base coverage: %v\n", err)
		return 2
	}
	head, err := loadCoverage(*headPath)
	if err != nil {
		fmt.Fprintf(stderr, "head coverage: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "Base: %s (%d/%d statements)\nPR:   %s (%d/%d statements)\n", base.percent(), base.covered, base.total, head.percent(), head.covered, head.total)
	// Compare exact fractions, not rounded percentages or overflowing products.
	if head.ratio().Cmp(base.ratio()) < 0 {
		fmt.Fprintln(stderr, "FAIL: statement coverage decreased")
		return 1
	}
	fmt.Fprintln(stdout, "PASS: statement coverage did not decrease")
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
