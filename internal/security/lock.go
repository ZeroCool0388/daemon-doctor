package security

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// lockState serializes state transactions across stores and processes.
// The caller holds s.mu. State is refreshed only after obtaining the lock,
// so a store opened before another process consumed a nonce cannot reuse it.
func (s *Store) lockState() (func(), error) {
	return s.lockStateContext(context.Background())
}
func (s *Store) lockStateContext(ctx context.Context) (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := LockFileContext(ctx, int(f.Fd())); err != nil {
		f.Close()
		return nil, err
	}
	unlock := func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
	if err := s.load(); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func lockIdentity(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "identity.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// LockMutexContext and LockFileContext wait without leaving a detached waiter
// behind when a remote request times out or its outbound link closes.
func LockMutexContext(ctx context.Context, mu *sync.Mutex) error {
	return waitLock(ctx, func() (bool, error) { return mu.TryLock(), nil }, mu.Unlock)
}

func LockFileContext(ctx context.Context, fd int) error {
	return waitLock(ctx, func() (bool, error) {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return false, nil
		}
		return err == nil, err
	}, func() { _ = syscall.Flock(fd, syscall.LOCK_UN) })
}

func waitLock(ctx context.Context, try func() (bool, error), unlock func()) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		locked, err := try()
		if err != nil {
			return err
		}
		if locked {
			if err := ctx.Err(); err != nil {
				unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
