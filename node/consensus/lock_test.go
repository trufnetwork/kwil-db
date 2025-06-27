package consensus_test

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/utils/random"
	"github.com/trufnetwork/kwil-db/node/consensus"
)

func TestPriorityLockQueue(t *testing.T) {
	pl := consensus.PriorityLockQueue{}

	// Simulate queue calls
	for i := 1; i <= 3; i++ {
		go func(id int) {
			pl.Lock()
			fmt.Printf("Queue %d acquired lock\n", id)
			time.Sleep(1 * time.Second)
			fmt.Printf("Queue %d released lock\n", id)
			pl.Unlock()
		}(i)
		runtime.Gosched()
	}

	time.Sleep(500 * time.Millisecond) // Allow queue to start

	// Commit takes priority
	go func() {
		pl.PriorityLock()
		fmt.Println("Commit acquired lock")
		time.Sleep(2 * time.Second)
		fmt.Println("Commit released lock")
		pl.Unlock()
	}()

	time.Sleep(5 * time.Second) // Wait for all routines to finish
}

func BenchmarkRegularLocks(b *testing.B) {
	const numWorkers = 100 // Fixed worker count
	var pl consensus.PriorityLockQueue
	var wg sync.WaitGroup

	b.ResetTimer()
	work := make(chan struct{}, numWorkers)

	// Create fixed worker pool
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work { // Consume work
				pl.Lock()
				time.Sleep(10 * time.Microsecond) // Simulate work
				pl.Unlock()
			}
		}()
	}

	// Feed the workers `b.N` operations
	for range b.N {
		work <- struct{}{}
	}
	close(work) // Signal workers to exit
	wg.Wait()
}

func BenchmarkPriorityLocks(b *testing.B) {
	const numWorkers = 100 // Fixed worker count
	var pl consensus.PriorityLockQueue
	var wg sync.WaitGroup

	b.ResetTimer()
	work := make(chan struct{}, numWorkers)

	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				pl.PriorityLock()
				time.Sleep(10 * time.Microsecond)
				pl.Unlock()
			}
		}()
	}

	for range b.N {
		work <- struct{}{}
	}
	close(work)
	wg.Wait()
}

func BenchmarkMutexLocks(b *testing.B) {
	const numWorkers = 100 // Fixed worker count
	var pl sync.Mutex
	var wg sync.WaitGroup

	b.ResetTimer()
	work := make(chan struct{}, numWorkers)

	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				pl.Lock()
				time.Sleep(10 * time.Microsecond)
				pl.Unlock()
			}
		}()
	}

	for range b.N {
		work <- struct{}{}
	}
	close(work)
	wg.Wait()
}

func BenchmarkMixedPriorityLocks(b *testing.B) {
	const numWorkers = 40 // Fixed worker count
	var pl consensus.PriorityLockQueue
	var wg sync.WaitGroup

	var lt, pt atomic.Int64
	var np, nl atomic.Int64

	b.ResetTimer()
	for range numWorkers { // Fixed number of goroutines
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range max(1, b.N/numWorkers) { // Spread iterations across workers
				t0 := time.Now()
				priority := random.Source.Uint64()%20 == 0
				if priority {
					pl.PriorityLock()
					pt.Add(int64(time.Since(t0)))
					np.Add(1)
				} else {
					pl.Lock()
					lt.Add(int64(time.Since(t0)))
					nl.Add(1)
				}
				time.Sleep(time.Microsecond) // Simulate work
				pl.Unlock()
			}
		}()
	}

	wg.Wait()

	if np.Load() > 0 {
		b.Log(time.Duration(lt.Load()/nl.Load()), time.Duration(pt.Load()/np.Load()))
	}
}
