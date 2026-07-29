// Command coveragegate enforces EnvGuardian's statement-coverage release
// floors from a Go coverprofile.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const overallFloor = 80.0

var packageFloors = map[string]float64{
	"crypt":  85.0,
	"config": 85.0,
	"keys":   85.0,
	"dotenv": 85.0,
}

type counter struct {
	covered int
	total   int
}

func (c counter) percent() float64 {
	if c.total == 0 {
		return 0
	}
	return float64(c.covered) * 100 / float64(c.total)
}

func packageName(filename string) string {
	marker := "/internal/"
	index := strings.Index(filepathSlash(filename), marker)
	if index < 0 {
		return ""
	}
	rest := filepathSlash(filename)[index+len(marker):]
	name, _, _ := strings.Cut(rest, "/")
	return name
}

func filepathSlash(value string) string { return strings.ReplaceAll(value, `\`, "/") }

func readProfile(path string) (counter, map[string]counter, error) {
	file, err := os.Open(path) //nolint:gosec // CI-provided local coverprofile
	if err != nil {
		return counter{}, nil, fmt.Errorf("open coverage profile: %w", err)
	}
	defer file.Close()

	packages := make(map[string]counter)
	var overall counter
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if !strings.HasPrefix(line, "mode: ") {
				return counter{}, nil, errors.New("coverage profile has no mode header")
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return counter{}, nil, errors.New("coverage profile contains a malformed record")
		}
		statements, statErr := strconv.Atoi(fields[1])
		count, countErr := strconv.ParseUint(fields[2], 10, 64)
		if statErr != nil || countErr != nil || statements < 0 {
			return counter{}, nil, errors.New("coverage profile contains an invalid count")
		}
		overall.total += statements
		if count > 0 {
			overall.covered += statements
		}
		filename, _, ok := strings.Cut(fields[0], ":")
		if !ok {
			return counter{}, nil, errors.New("coverage profile record has no filename")
		}
		name := packageName(filename)
		if name != "" {
			value := packages[name]
			value.total += statements
			if count > 0 {
				value.covered += statements
			}
			packages[name] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return counter{}, nil, fmt.Errorf("read coverage profile: %w", err)
	}
	if first || overall.total == 0 {
		return counter{}, nil, errors.New("coverage profile contains no statements")
	}
	return overall, packages, nil
}

func validate(overall counter, packages map[string]counter) error {
	var failures []string
	for name, floor := range packageFloors {
		value := packages[name]
		fmt.Printf("coverage %-8s %5.1f%% (minimum %.1f%%)\n", name, value.percent(), floor)
		if value.percent()+0.0001 < floor {
			failures = append(failures, name)
		}
	}
	fmt.Printf("coverage overall  %5.1f%% (minimum %.1f%%)\n", overall.percent(), overallFloor)
	if overall.percent()+0.0001 < overallFloor {
		failures = append(failures, "overall")
	}
	if len(failures) > 0 {
		return fmt.Errorf("coverage below required floor: %s", strings.Join(failures, ", "))
	}
	return nil
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: coveragegate COVERPROFILE")
	}
	overall, packages, err := readProfile(args[0])
	if err != nil {
		return err
	}
	return validate(overall, packages)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(1)
	}
}
