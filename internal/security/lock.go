package security

import (
	"os"
	"path/filepath"
	"syscall"
)

// lockState serializes state transactions across stores and processes.
// The caller holds s.mu. State is refreshed only after obtaining the lock,
// so a store opened before another process consumed a nonce cannot reuse it.
func (s *Store) lockState() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
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
