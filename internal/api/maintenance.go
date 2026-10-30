package api

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// StorePurger defines the interface for cleaning expired invites.
type StorePurger interface {
	PurgeExpiredInvites(ctx context.Context, retentionSeconds int64) (int, error)
}

// MaintenanceManager runs periodic cleanup tasks.
type MaintenanceManager struct {
	store            StorePurger
	log              *slog.Logger
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	retentionSeconds int64
	tickInterval     time.Duration
}

// MaintenanceManagerOption configures a MaintenanceManager.
type MaintenanceManagerOption func(*MaintenanceManager)

// WithTickInterval sets the interval between purge runs (default 1 hour).
func WithTickInterval(d time.Duration) MaintenanceManagerOption {
	return func(m *MaintenanceManager) {
		m.tickInterval = d
	}
}

// NewMaintenanceManager creates and starts a maintenance manager.
func NewMaintenanceManager(ctx context.Context, store StorePurger, log *slog.Logger, retentionSeconds int64, opts ...MaintenanceManagerOption) *MaintenanceManager {
	ctx, cancel := context.WithCancel(ctx)
	m := &MaintenanceManager{
		store:            store,
		log:              log,
		ctx:              ctx,
		cancel:           cancel,
		retentionSeconds: retentionSeconds,
		tickInterval:     1 * time.Hour,
	}

	for _, opt := range opts {
		opt(m)
	}

	m.wg.Add(1)
	go m.maintenanceLoop()

	return m
}

// maintenanceLoop periodically purges expired invites.
func (m *MaintenanceManager) maintenanceLoop() {
	defer m.wg.Done()

	// Run once immediately at startup
	m.purgeExpired()

	// Then run every hour
	ticker := time.NewTicker(m.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.purgeExpired()
		}
	}
}

func (m *MaintenanceManager) purgeExpired() {
	count, err := m.store.PurgeExpiredInvites(m.ctx, m.retentionSeconds)
	if err != nil {
		m.log.Error("maintenance: purge failed", "err", err)
	} else if count > 0 {
		m.log.Info("maintenance: purged invites", "count", count)
	}
}

// Stop gracefully stops the maintenance manager.
func (m *MaintenanceManager) Stop() {
	m.cancel()
	m.wg.Wait()
}
