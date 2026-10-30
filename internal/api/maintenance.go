package api

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// StorePurger defines the interface for cleaning expired invites.
type StorePurger interface {
	PurgeExpiredInvites(ctx context.Context, retentionSeconds int64) (deleted int, more bool, err error)
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
	followUpInterval     time.Duration
	more                 bool
	rebuildInterval      time.Duration
	lastRebuild          time.Time
	rebuildIntervalHours int
}

// MaintenanceManagerOption configures a MaintenanceManager.
type MaintenanceManagerOption func(*MaintenanceManager)

// WithTickInterval sets the interval between purge runs (default 1 hour).
func WithTickInterval(d time.Duration) MaintenanceManagerOption {
	return func(m *MaintenanceManager) {
		if d > 0 {
			m.tickInterval = d
		}
	}
}

// WithFollowUpInterval sets the delay before the next run after a capped purge (default 1 minute).
func WithFollowUpInterval(d time.Duration) MaintenanceManagerOption {
	return func(m *MaintenanceManager) {
		if d > 0 {
			m.followUpInterval = d
		}
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
		followUpInterval:     1 * time.Minute,
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
	m.more = m.purgeExpired()
	m.reconcileKeyIndex()

	// Then run every tick interval, or after followUpInterval when a capped run left a backlog
	timer := time.NewTimer(m.nextDelay())
	defer timer.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-timer.C:
			m.more = m.purgeExpired()
			m.reconcileKeyIndex()
			timer.Reset(m.nextDelay())
		}
	}
}

func (m *MaintenanceManager) nextDelay() time.Duration {
	if m.more {
		return min(m.followUpInterval, m.tickInterval)
	}
	return m.tickInterval
}

// purgeExpired reports whether a backlog remains.
func (m *MaintenanceManager) purgeExpired() bool {
	count, more, err := m.store.PurgeExpiredInvites(m.ctx, m.retentionSeconds)
	if count > 0 {
		m.log.Info("maintenance: purged invites", "count", count, "more", more)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		m.log.Error("maintenance: purge failed", "err", err)
	}
	return more
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
