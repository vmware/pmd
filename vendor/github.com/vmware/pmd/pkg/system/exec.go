// SPDX-License-Identifier: BSD-2
// Copyright 2022 VMware, Inc.

package system

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func ExecAndDisplay(w io.Writer, cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	if out, err := c.CombinedOutput(); err != nil {
		return err
	} else {
		fmt.Fprintf(w, "%s\n", out)
		return nil
	}
}

func ExecAndCapture(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	if out, err := c.CombinedOutput(); err != nil {
		return "", err
	} else {
		return string(out), nil
	}
}

func ExecAndRenounce(cmds ...string) error {
	binary, err := exec.LookPath(cmds[0])
	if err != nil {
		return nil
	}

	return unix.Exec(binary, cmds, unix.Environ())

}

func ExecRun(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	return  c.Start()
}

func ExecAndShowProgess(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	c.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
	c.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	if err := c.Run(); err != nil {
		return err
	}

	out, err := string(stdoutBuf.String()), string(stderrBuf.String())
	fmt.Printf("\n%s\n%s\n", out, err)

	return nil
}

func ExecInteractive(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)

	var stdoutBuf, stderrBuf, stdinBuf bytes.Buffer
	c.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
	c.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	c.Stdin = io.MultiReader(os.Stdin, &stdinBuf)

	if err := c.Run(); err != nil {
		return err
	}

	out, err := string(stdoutBuf.String()), string(stderrBuf.String())
	fmt.Printf("\n%s\n%s\n", out, err)
	c.Wait()

	return nil
}
