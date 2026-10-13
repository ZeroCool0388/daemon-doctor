// Package offers persists single-use local fix capabilities. It has no phone keys.
package offers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/security"
)

type Offer struct {
	ID          string    `json:"offer_id"`
	AlertID     string    `json:"alert_id"`
	ServiceID   string    `json:"service_id"`
	ServiceName string    `json:"service_name"`
	FixID       string    `json:"fix_id"`
	Message     string    `json:"message"`
	ExpiresAt   time.Time `json:"expires_at"`
	Consumed    bool      `json:"consumed"`
}

type Store struct {
	mu    sync.Mutex
	dir   string
	items map[string]Offer
}

// Open uses a dedicated private directory; an empty path is memory-only for demos.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir, items: map[string]Offer{}}
	if dir != "" {
		if err := PrivateDir(dir); err != nil {
			return nil, err
		}
		if err := s.transaction(func() error { return nil }); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, owned := info.Sys().(*syscall.Stat_t)
	if !owned || st.Uid != uint32(os.Getuid()) || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("control directory must be a real directory with mode 0700")
	}
	return nil
}

// transaction refreshes disk state only after obtaining the cross-process lock.
func (s *Store) transaction(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return fn()
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "offers.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	data, err := os.ReadFile(filepath.Join(s.dir, "offers.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.items = map[string]Offer{}
	if len(data) > 0 {
		if err = json.Unmarshal(data, &s.items); err != nil {
			return fmt.Errorf("read offers: %w", err)
		}
	}
	return fn()
}

func (s *Store) save() error {
	if s.dir == "" {
		return nil
	}
	data, err := json.Marshal(s.items)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".offers-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, "offers.json")); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) Mint(now time.Time, alert security.Raised, message string) error {
	return s.transaction(func() error {
		for id, o := range s.items {
			if !now.Before(o.ExpiresAt) {
				delete(s.items, id)
			}
		}
		for _, fix := range alert.Actions {
			id := security.NewID()
			s.items[id] = Offer{ID: id, AlertID: alert.ID, ServiceID: alert.ServiceID, ServiceName: alert.ServiceName, FixID: fix, Message: message, ExpiresAt: alert.At.Add(security.ApprovalTTL)}
		}
		return s.save()
	})
}

func (s *Store) List(now time.Time) ([]Offer, error) {
	out := []Offer{}
	err := s.transaction(func() error {
		for _, o := range s.items {
			if !o.Consumed && now.Before(o.ExpiresAt) {
				out = append(out, o)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// Consume persists the burn before returning. All actions for the same incident
// are burned together, including when execution later fails or is cancelled.
func (s *Store) Consume(now time.Time, id string, validate func(Offer) error) (Offer, error) {
	var out Offer
	err := s.transaction(func() error {
		o, ok := s.items[id]
		if !ok {
			return fmt.Errorf("unknown fix offer")
		}
		if o.Consumed {
			return fmt.Errorf("fix offer already consumed (replay)")
		}
		if !now.Before(o.ExpiresAt) {
			return fmt.Errorf("fix offer expired")
		}
		if err := validate(o); err != nil {
			return err
		}
		for key, item := range s.items {
			if item.AlertID == o.AlertID {
				item.Consumed = true
				s.items[key] = item
			}
		}
		if err := s.save(); err != nil {
			return err
		}
		out = o
		return nil
	})
	return out, err
}
