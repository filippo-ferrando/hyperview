package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"hyperview/internal/collect"
	"hyperview/internal/store"
	"hyperview/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	domainStore := store.NewDomainStore()
	registry := collect.NewRegistry()
	registry.Register(collect.NewMockCollector())

	// Data collection tick runner running asynchronously
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, col := range registry.Collectors() {
					_ = col.Collect(ctx, domainStore)
				}
			}
		}
	}()

	// Instantiate and initialize the TUI layer
	p := tea.NewProgram(tui.NewRootModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Printf("Fatal runtime TUI crash: %v", err)
		os.Exit(1)
	}

	for _, col := range registry.Collectors() {
		_ = col.Close()
	}
	fmt.Println("Clean shutdown completed.")
}
