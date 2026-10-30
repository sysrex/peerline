package api

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// StorePurger defines the interface for cleaning expired invites.
type StorePurger interface {
	PurgeExpiredInvites(ctx context.Context) (int, error)
}

// MaintenanceManager runs periodic cleanup tasks.
type MaintenanceManager struct {
	store  StorePurger
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewMaintenanceManager creates and starts a maintenance manager.
func NewMaintenanceManager(ctx context.Context, store StorePurger, log *slog.Logger) *MaintenanceManager {
	ctx, cancel := context.WithCancel(ctx)
	m := &MaintenanceManager{
		store:  store,
		log:    log,
		ctx:    ctx,
		cancel: cancel,
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
	ticker := time.NewTicker(1 * time.Hour)
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
	count, err := m.store.PurgeExpiredInvites(m.ctx)
	if err != nil {
		m.log.Error("maintenance: purge failed", "err", err)
	} else if count > 0 {
		m.log.Info("maintenance: purged expired invites", "count", count)
	}
}

// Stop gracefully stops the maintenance manager.
func (m *MaintenanceManager) Stop() {
	m.cancel()
	m.wg.Wait()
}
