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
	ReconcileKeyIndex(ctx context.Context, forceRebuild bool) (rebuilt bool, err error)
}

// MaintenanceManager runs periodic cleanup tasks.
type MaintenanceManager struct {
	store                StorePurger
	log                  *slog.Logger
	ctx                  context.Context
	cancel               context.CancelFunc
	wg                   sync.WaitGroup
	retentionSeconds     int64
	tickInterval         time.Duration
	rebuildInterval      time.Duration
	lastRebuild          time.Time
	rebuildIntervalHours int
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
func NewMaintenanceManager(ctx context.Context, store StorePurger, log *slog.Logger, retentionSeconds int64, rebuildIntervalHours int, opts ...MaintenanceManagerOption) *MaintenanceManager {
	ctx, cancel := context.WithCancel(ctx)
	if rebuildIntervalHours <= 0 {
		rebuildIntervalHours = 6 // default: rebuild every 6 hours
	}
	m := &MaintenanceManager{
		store:                store,
		log:                  log,
		ctx:                  ctx,
		cancel:               cancel,
		retentionSeconds:     retentionSeconds,
		tickInterval:         1 * time.Hour,
		rebuildInterval:      time.Duration(rebuildIntervalHours) * time.Hour,
		rebuildIntervalHours: rebuildIntervalHours,
		lastRebuild:          time.Now(), // start timer from now
	}

	for _, opt := range opts {
		opt(m)
	}

	m.wg.Add(1)
	go m.maintenanceLoop()

	return m
}

// maintenanceLoop periodically purges expired invites and reconciles the key index.
func (m *MaintenanceManager) maintenanceLoop() {
	defer m.wg.Done()

	// Run once immediately at startup
	m.purgeExpired()
	m.reconcileKeyIndex()

	// Then run every tickInterval
	ticker := time.NewTicker(m.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.purgeExpired()
			m.reconcileKeyIndex()
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

// reconcileKeyIndex checks the key index count against the peer count every tick,
// and does a full rebuild if they differ or if rebuildInterval has elapsed.
func (m *MaintenanceManager) reconcileKeyIndex() {
	// Check if it's time for a periodic full rebuild
	forceRebuild := time.Since(m.lastRebuild) >= m.rebuildInterval

	rebuilt, err := m.store.ReconcileKeyIndex(m.ctx, forceRebuild)
	if err != nil {
		m.log.Error("maintenance: key index reconcile failed", "err", err)
		return
	}

	if rebuilt {
		reason := "count mismatch"
		if forceRebuild {
			reason = "periodic rebuild"
		}
		m.log.Info("maintenance: key index rebuilt", "reason", reason)
		m.lastRebuild = time.Now()
	}
}

// Stop gracefully stops the maintenance manager.
func (m *MaintenanceManager) Stop() {
	m.cancel()
	m.wg.Wait()
}
