package singledo

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

func TestBasic(t *testing.T) {
	single := NewSingle(time.Millisecond * 30)
	foo := 0
	shardCount := atomic.NewInt32(0)
	call := func() (interface{}, error) {
		foo++
		time.Sleep(time.Millisecond * 5)
		return nil, nil
	}

	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, shard := single.Do(call)
			if shard {
				shardCount.Inc()
			}
			wg.Done()
		}()
	}

	wg.Wait()
	assert.Equal(t, 1, foo)
	assert.Equal(t, int32(4), shardCount.Load())
}

func TestTimer(t *testing.T) {
	single := NewSingle(time.Millisecond * 30)
	foo := 0
	call := func() (interface{}, error) {
		foo++
		return nil, nil
	}

	single.Do(call)
	time.Sleep(10 * time.Millisecond)
	_, _, shard := single.Do(call)

	assert.Equal(t, 1, foo)
	assert.True(t, shard)
}

func TestReset(t *testing.T) {
	single := NewSingle(time.Millisecond * 30)
	foo := 0
	call := func() (interface{}, error) {
		foo++
		return nil, nil
	}

	single.Do(call)
	single.Reset()
	single.Do(call)

	assert.Equal(t, 2, foo)
}
