package safego

import (
	"sync"
	"testing"
)

func TestRecoverStopsPanicInGoroutine(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer Recover("test")
		panic("boom")
	}()
	wg.Wait() // reaching here means the process survived
}

func TestRunContinuesLoop(t *testing.T) {
	ran := 0
	for i := 0; i < 3; i++ {
		Run("test-loop", func() {
			ran++
			if ran == 2 {
				panic("tick failed")
			}
		})
	}
	if ran != 3 {
		t.Fatalf("ran = %d, want 3", ran)
	}
}

func TestRecoverNoPanic(t *testing.T) {
	called := false
	Run("noop", func() { called = true })
	if !called {
		t.Fatal("fn not called")
	}
}
