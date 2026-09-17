package housekeeping

import (
	"context"
	"sync"
	"time"
)

type Job struct {
	Name     string
	Interval time.Duration
	Step     func(ctx context.Context) error
	Wake     <-chan struct{}
}

type Scheduler struct {
	jobs    []Job
	onError func(job string, err error)
	wg      sync.WaitGroup
}

func New(jobs []Job, onError func(job string, err error)) *Scheduler {
	if onError == nil {
		onError = func(string, error) {}
	}
	return &Scheduler{jobs: jobs, onError: onError}
}

func (s *Scheduler) Run(ctx context.Context) {
	for _, job := range s.jobs {
		s.wg.Add(1)
		go func(j Job) {
			defer s.wg.Done()
			s.runJob(ctx, j)
		}(job)
	}
	s.wg.Wait()
}

func (s *Scheduler) runJob(ctx context.Context, job Job) {
	step := func() {
		if err := job.Step(ctx); err != nil && ctx.Err() == nil {
			s.onError(job.Name, err)
		}
	}
	if ctx.Err() != nil {
		return
	}
	step()
	ticker := time.NewTicker(job.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			step()
		case <-job.Wake:
			step()
		}
	}
}
