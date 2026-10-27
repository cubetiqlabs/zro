//go:build linux || darwin

package node

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
)

type ptyRequest struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32
	Modes         string
}

type windowChange struct{ Cols, Rows, Width, Height uint32 }

// serveSession runs one shell or command for an authenticated user.
func (d *Daemon) serveSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, username string) {
	defer ch.Close()
	var (
		pty     *ptyRequest
		ptmx    *os.File
		env     []string
		started bool
		mu      sync.Mutex
	)
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) != nil || started {
				_ = req.Reply(false, nil)
				continue
			}
			pty = &p
			_ = req.Reply(true, nil)
		case "window-change":
			var w windowChange
			mu.Lock()
			if ssh.Unmarshal(req.Payload, &w) == nil && ptmx != nil {
				setWinsize(ptmx, w.Cols, w.Rows)
			}
			mu.Unlock()
		case "env":
			var kv struct{ Name, Value string }
			ok := ssh.Unmarshal(req.Payload, &kv) == nil && (kv.Name == "LANG" || strings.HasPrefix(kv.Name, "LC_"))
			if ok {
				env = append(env, kv.Name+"="+kv.Value)
			}
			_ = req.Reply(ok, nil)
		case "shell", "exec":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			var command string
			if req.Type == "exec" {
				var c struct{ Command string }
				if ssh.Unmarshal(req.Payload, &c) != nil {
					_ = req.Reply(false, nil)
					continue
				}
				command = c.Command
			}
			cmd, err := loginCommand(username, command, env, pty)
			if err != nil {
				slog.Warn("SSH session refused", "user", username, "error", err)
				_, _ = fmt.Fprintf(ch.Stderr(), "zro: %v\r\n", err)
				_ = req.Reply(false, nil)
				return
			}
			started = true
			_ = req.Reply(true, nil)
			f, err := runSession(ch, cmd, pty)
			if err != nil {
				_, _ = fmt.Fprintf(ch.Stderr(), "zro: %v\r\n", err)
				return
			}
			mu.Lock()
			ptmx = f
			mu.Unlock()
			go func() {
				code := waitSession(ch, cmd, f)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				_ = ch.Close()
			}()
		default: // subsystem (sftp), auth-agent-req, x11-req, signal…
			_ = req.Reply(false, nil)
		}
	}
}

// loginCommand prepares the user's login shell (or shell -c command) as that user.
func loginCommand(username, command string, extraEnv []string, pty *ptyRequest) (*exec.Cmd, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("no local user %q", username)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	shell := loginShell(username)

	var cmd *exec.Cmd
	if command == "" {
		cmd = exec.Command(shell)
		cmd.Args[0] = "-" + filepath.Base(shell) // login shell
	} else {
		cmd = exec.Command(shell, "-c", command)
	}
	cmd.Dir = u.HomeDir
	cmd.Env = append([]string{
		"HOME=" + u.HomeDir, "USER=" + username, "LOGNAME=" + username, "SHELL=" + shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}, extraEnv...)
	if pty != nil && pty.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+pty.Term)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	switch {
	case os.Geteuid() == 0:
		var groups []uint32
		if ids, err := u.GroupIds(); err == nil {
			for _, g := range ids {
				if n, err := strconv.ParseUint(g, 10, 32); err == nil {
					groups = append(groups, uint32(n))
				}
			}
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}
	case strconv.Itoa(os.Geteuid()) != u.Uid:
		return nil, fmt.Errorf("the zro daemon runs as uid %d and can only log in as itself; run it as root to log in as %s", os.Geteuid(), username)
	}
	return cmd, nil
}

// loginShell reads the user's shell from /etc/passwd, defaulting to /bin/sh.
func loginShell(username string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) == 7 && fields[0] == username && fields[6] != "" {
			return fields[6]
		}
	}
	return "/bin/sh"
}

// runSession starts cmd wired to the channel, through a PTY when one was
// requested. It returns the PTY master (nil without one).
func runSession(ch ssh.Channel, cmd *exec.Cmd, pty *ptyRequest) (*os.File, error) {
	if pty == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
		return nil, cmd.Start()
	}
	ptmx, tty, err := openPTY()
	if err != nil {
		return nil, err
	}
	if cmd.SysProcAttr.Credential != nil {
		_ = tty.Chown(int(cmd.SysProcAttr.Credential.Uid), -1)
	}
	setWinsize(ptmx, pty.Cols, pty.Rows)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr.Setctty = true
	if err := cmd.Start(); err != nil {
		ptmx.Close()
		tty.Close()
		return nil, err
	}
	tty.Close() // the child holds it now
	go func() { _, _ = io.Copy(ptmx, ch) }()
	return ptmx, nil
}

// waitSession waits for the command and for its output to drain, and returns
// the exit code.
func waitSession(ch ssh.Channel, cmd *exec.Cmd, ptmx *os.File) int {
	var drained chan struct{}
	if ptmx != nil {
		drained = make(chan struct{})
		go func() { _, _ = io.Copy(ch, ptmx); close(drained) }() // ends with EIO once the child side closes
	}
	err := cmd.Wait()
	if ptmx != nil {
		<-drained
		ptmx.Close()
	}
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}
