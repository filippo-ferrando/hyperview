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

	// Register live polling integrations
	registry.Register(collect.NewLibvirtCollector("/var/run/libvirt/libvirt-sock"))

	procColl, err := collect.NewProcCollector()
	if err == nil {
		registry.Register(procColl)
	} else {
		log.Printf("Warning: Host OS procfs collection engine offline: %v", err)
	}

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

	// Instantiate full Phase 1 composite matrix
	p := tea.NewProgram(tui.NewRootModel(domainStore), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Printf("Fatal runtime TUI crash: %v", err)
		os.Exit(1)
	}

	for _, col := range registry.Collectors() {
		_ = col.Close()
	}
	fmt.Println("Clean shutdown completed.")
}
