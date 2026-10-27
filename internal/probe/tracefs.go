package probe

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// Field is one entry of a tracepoint format description.
type Field struct {
	Name   string
	Offset uint32
	Size   uint32
}

// tracepointFormat reads the field layout of group/name from tracefs.
func tracepointFormat(group, name string) (map[string]Field, error) {
	var errs []error
	for _, root := range tracefsRoots {
		f, err := os.Open(filepath.Join(root, "events", group, name, "format"))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		defer f.Close()
		return parseFormat(f)
	}
	if allNotExist(errs) {
		return nil, fmt.Errorf("tracepoint %s:%s not available", group, name)
	}
	return nil, errors.Join(errs...)
}

func allNotExist(errs []error) bool {
	for _, err := range errs {
		if !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// parseFormat parses lines like
//
//	field:unsigned int exit_reason;	offset:8;	size:4;	signed:0;
func parseFormat(r interface{ Read([]byte) (int, error) }) (map[string]Field, error) {
	fields := make(map[string]Field)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "field:") {
			continue
		}
		var fd Field
		for _, part := range strings.Split(line, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), ":")
			if !ok {
				continue
			}
			switch k {
			case "field":
				decl := strings.Fields(v)
				if len(decl) == 0 {
					continue
				}
				n := decl[len(decl)-1]
				if i := strings.IndexByte(n, '['); i >= 0 {
					n = n[:i]
				}
				fd.Name = n
			case "offset":
				o, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("bad offset in %q", line)
				}
				fd.Offset = uint32(o)
			case "size":
				s, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("bad size in %q", line)
				}
				fd.Size = uint32(s)
			}
		}
		if fd.Name != "" {
			fields[fd.Name] = fd
		}
	}
	return fields, sc.Err()
}
