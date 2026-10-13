package doctor

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// stateMutex queues both check cycles and backend requests on the same lock.
// Polling TryLock lets an overdue monitor ticker repeatedly reacquire the lock
// ahead of readers. A one-slot weighted semaphore gives queued callers a turn
// and removes cancelled waiters without starting a detached goroutine.
// The zero value is ready to use, including in tests that construct a Doctor.
type stateMutex struct {
	once      sync.Once
	semaphore *semaphore.Weighted
}

func (m *stateMutex) init() {
	m.once.Do(func() { m.semaphore = semaphore.NewWeighted(1) })
}

func (m *stateMutex) LockContext(ctx context.Context) error {
	m.init()
	if err := m.semaphore.Acquire(ctx, 1); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		m.semaphore.Release(1)
		return err
	}
	return nil
}

func (m *stateMutex) Lock()   { _ = m.LockContext(context.Background()) }
func (m *stateMutex) Unlock() { m.init(); m.semaphore.Release(1) }
