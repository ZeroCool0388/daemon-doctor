package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
)

const MaxRequestBytes = 64 << 10
const MaxResponseBytes = 4 << 20
const RequestTimeout = time.Minute

type response struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}
type Server struct {
	listener  *net.UnixListener
	lock      *os.File
	path      string
	inode     os.FileInfo
	backend   Backend
	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	closing   bool
}

func Listen(path string, backend Backend) (*Server, error) {
	if err := offers.PrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			lock.Close()
		}
	}()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("control socket already in use")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket control path")
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Getuid()) {
			return nil, fmt.Errorf("control socket belongs to another user")
		}
		if conn, e := net.DialTimeout("unix", path, 100*time.Millisecond); e == nil {
			conn.Close()
			return nil, fmt.Errorf("control socket already has a listener")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		listener.Close()
		return nil, err
	}
	failed = false
	return &Server{listener: listener, lock: lock, path: path, inode: info, backend: backend, conns: map[net.Conn]struct{}{}}, nil
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.listener.Close()
		s.mu.Lock()
		s.closing = true
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if info, e := os.Lstat(s.path); e == nil && os.SameFile(info, s.inode) {
			_ = os.Remove(s.path)
		}
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
	})
	return err
}

func (s *Server) Serve(ctx context.Context) error {
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-stopped:
		}
	}()
	defer s.Close()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if s.closing || len(s.conns) >= 32 {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); delete(s.conns, conn); s.mu.Unlock() }()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(parent context.Context, c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(RequestTimeout))
	ctx, cancel := context.WithTimeout(parent, RequestTimeout)
	defer cancel()
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), MaxRequestBytes)
	var req Request
	var data any
	var err error
	if !scan.Scan() {
		err = fmt.Errorf("missing or oversized control request")
	} else {
		dec := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&req); err == nil {
			var extra any
			if dec.Decode(&extra) != io.EOF {
				err = fmt.Errorf("one JSON request is required")
			}
		}
		if err == nil {
			data, err = s.backend.Call(ctx, req)
		}
	}
	res := response{}
	if err != nil {
		res.Error = logbook.Blank(err.Error())
	} else {
		res.Data, err = Sanitize(data)
		if err != nil {
			res.Error = "encode control response"
		}
	}
	_ = json.NewEncoder(c).Encode(res)
}

// Sanitize applies the existing secret blanker to every string, preserving JSON.
func Sanitize(data any) ([]byte, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var value any
	if err = json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			return logbook.Blank(x)
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for k := range x {
				x[k] = walk(x[k])
			}
		}
		return v
	}
	return json.Marshal(walk(value))
}

type Client struct{ Path string }

func (c *Client) Call(ctx context.Context, r Request) (any, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, fmt.Errorf("daemon control socket unavailable; is daemon-doctor run active with control enabled? %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(RequestTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	if err = json.NewEncoder(conn).Encode(r); err != nil {
		return nil, err
	}
	scan := bufio.NewScanner(conn)
	scan.Buffer(make([]byte, 4096), MaxResponseBytes)
	if !scan.Scan() {
		if err = scan.Err(); err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	var res response
	if err = json.Unmarshal(scan.Bytes(), &res); err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, errors.New(res.Error)
	}
	var value any
	err = json.Unmarshal(res.Data, &value)
	return value, err
}
