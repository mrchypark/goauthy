// goauthy-password prints an Argon2id PHC credential for a password piped on stdin.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/mrchypark/goauthy/internal/credential"
)

const maxPasswordBytes = 1024

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "goauthy-password:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out io.Writer) error {
	policy, err := policyFromArgs(args)
	if err != nil {
		return err
	}
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		return fmt.Errorf("configure Argon2 password policy: %w", err)
	}
	password, err := readPassword(in)
	if err != nil {
		return err
	}
	phc, err := hasher.Hash(context.Background(), password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = fmt.Fprintln(out, phc)
	return err
}

func policyFromArgs(args []string) (credential.Policy, error) {
	defaults := credential.DefaultPolicy()
	flags := flag.NewFlagSet("goauthy-password", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	memory := flags.String("memory-kib", strconv.FormatUint(uint64(defaults.MemoryKiB), 10), "Argon2 memory in KiB")
	iterations := flags.String("iterations", strconv.FormatUint(uint64(defaults.Iterations), 10), "Argon2 iterations")
	parallelism := flags.String("parallelism", strconv.FormatUint(uint64(defaults.Parallelism), 10), "Argon2 parallelism")
	if err := flags.Parse(args); err != nil {
		return credential.Policy{}, err
	}
	if flags.NArg() != 0 {
		return credential.Policy{}, errors.New("goauthy-password accepts no positional arguments")
	}
	policy := defaults
	var err error
	if policy.MemoryKiB, err = flagUint32("memory-kib", *memory); err != nil {
		return credential.Policy{}, err
	}
	if policy.Iterations, err = flagUint32("iterations", *iterations); err != nil {
		return credential.Policy{}, err
	}
	if policy.Parallelism, err = flagUint8("parallelism", *parallelism); err != nil {
		return credential.Policy{}, err
	}
	if _, err := credential.NewHasher(policy); err != nil {
		return credential.Policy{}, fmt.Errorf("invalid Argon2 password policy: %w", err)
	}
	return policy, nil
}

func flagUint32(name, raw string) (uint32, error) {
	value, err := flagUint(name, raw, 32)
	return uint32(value), err
}

func flagUint8(name, raw string) (uint8, error) {
	value, err := flagUint(name, raw, 8)
	return uint8(value), err
}

func flagUint(name, raw string, bits int) (uint64, error) {
	if raw == "" {
		return 0, fmt.Errorf("-%s must be an unsigned decimal integer", name)
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("-%s must be an unsigned decimal integer", name)
		}
	}
	value, err := strconv.ParseUint(raw, 10, bits)
	if err != nil || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("-%s must be an unsigned decimal integer", name)
	}
	return value, nil
}

func readPassword(in io.Reader) ([]byte, error) {
	input, err := io.ReadAll(io.LimitReader(in, maxPasswordBytes+3))
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(input) > maxPasswordBytes+2 {
		return nil, errors.New("password is too long")
	}
	if i := bytes.IndexByte(input, '\n'); i >= 0 {
		if i != len(input)-1 {
			return nil, errors.New("password must be one line")
		}
		input = input[:i]
	}
	if len(input) > 0 && input[len(input)-1] == '\r' {
		input = input[:len(input)-1]
	}
	if len(input) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if len(input) > maxPasswordBytes {
		return nil, errors.New("password is too long")
	}
	return input, nil
}
