package syncer

import (
	"context"

	"github.com/Havens-blog/e-iam/pkg/web/capability"
)

// Reporter 资产上报契约
type Reporter = capability.IReporter

// Registry 兼容历史别名
type Registry = capability.Registry

// ISyncer 资产同步调度引擎接口
type ISyncer interface {
	WithOption(opts ...capability.SyncOption) ISyncer
	Sync(ctx context.Context) error
}

type defaultSyncer struct {
	reporter  capability.IReporter
	collector *capability.Collector
}

// New 构造函数，调度 Collector 收集资产并上报
func New(reporter capability.IReporter, opts ...capability.SyncOption) ISyncer {
	s := &defaultSyncer{
		reporter:  reporter,
		collector: capability.NewCollector(),
	}
	if len(opts) > 0 {
		s.WithOption(opts...)
	}
	return s
}

func (s *defaultSyncer) WithOption(opts ...capability.SyncOption) ISyncer {
	for _, opt := range opts {
		opt(s.collector)
	}
	return s
}

func (s *defaultSyncer) Sync(ctx context.Context) error {
	req := s.collector.Collect()
	return s.reporter.Sync(ctx, req)
}
