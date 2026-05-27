package collect

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"sync"
	"time"

	"hyperview/internal/store"

	"github.com/digitalocean/go-libvirt"
)

type prevNetKey struct {
	domain string
	iface  string
}

type prevDiskKey struct {
	domain string
	disk   string
}

type DomainXML struct {
	Devices struct {
		Disks []struct {
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"disk"`
		Interfaces []struct {
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"interface"`
	} `xml:"devices"`
}

type LibvirtCollector struct {
	mu          sync.Mutex
	sockPath    string
	conn        net.Conn
	l           *libvirt.Libvirt
	prevCpuTime map[string][]uint64
	prevTick    map[string]time.Time
	prevIfaceRx map[prevNetKey]uint64
	prevIfaceTx map[prevNetKey]uint64
	prevDiskRd  map[prevDiskKey]uint64
	prevDiskWr  map[prevDiskKey]uint64
}

func NewLibvirtCollector(sockPath string) *LibvirtCollector {
	return &LibvirtCollector{
		sockPath:    sockPath,
		prevCpuTime: make(map[string][]uint64),
		prevTick:    make(map[string]time.Time),
		prevIfaceRx: make(map[prevNetKey]uint64),
		prevIfaceTx: make(map[prevNetKey]uint64),
		prevDiskRd:  make(map[prevDiskKey]uint64),
		prevDiskWr:  make(map[prevDiskKey]uint64),
	}
}

func (lc *LibvirtCollector) Name() string {
	return "libvirt"
}

func (lc *LibvirtCollector) connect() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.l != nil {
		return nil
	}

	conn, err := net.DialTimeout("unix", lc.sockPath, 2*time.Second)
	if err != nil {
		return err
	}

	l := libvirt.New(conn)
	if err := l.Connect(); err != nil {
		conn.Close()
		return err
	}

	lc.conn = conn
	lc.l = l
	return nil
}

func (lc *LibvirtCollector) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.conn != nil {
		_ = lc.l.Disconnect()
		err := lc.conn.Close()
		lc.l = nil
		lc.conn = nil
		return err
	}
	return nil
}

func (lc *LibvirtCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	if err := lc.connect(); err != nil {
		return fmt.Errorf("libvirt connection unavailable: %w", err)
	}

	domains, _, err := lc.l.ConnectListAllDomains(1, 0)
	if err != nil {
		lc.Close()
		return err
	}

	now := time.Now()

	for _, d := range domains {
		stateInt, _, err := lc.l.DomainGetState(d, 0)
		if err != nil {
			continue
		}

		stateStr := mapDomainState(stateInt)
		snap := store.DomainSnapshot{
			ID:          fmt.Sprintf("%x", d.UUID),
			Name:        d.Name,
			State:       stateStr,
			CollectedAt: now,
		}

		if stateStr == "running" {
			vcpuInfos, _, err := lc.l.DomainGetVcpus(d, 16, 1)
			if err == nil {
				lc.computeCpuPercentages(d.Name, vcpuInfos, &snap, now)
			}

			memStats, err := lc.l.DomainMemoryStats(d, 8, 0)
			if err == nil {
				for _, ms := range memStats {
					switch ms.Tag {
					case 6:
						snap.Mem.AllocKiB = ms.Val
					case 7:
						snap.Mem.AvailableKiB = ms.Val
					}
				}
			}

			xmlDesc, err := lc.l.DomainGetXMLDesc(d, 0)
			if err == nil {
				var domXML DomainXML
				if err := xml.Unmarshal([]byte(xmlDesc), &domXML); err == nil {

					// Pull virtual network interfaces
					for _, iface := range domXML.Devices.Interfaces {
						ifaceName := iface.Target.Dev
						if ifaceName == "" {
							continue
						}

						rxBytes, rxPackets, _, _, txBytes, txPackets, _, _, err := lc.l.DomainInterfaceStats(d, ifaceName)
						if err == nil {
							nk := prevNetKey{domain: d.Name, iface: ifaceName}
							rxDelta, txDelta := uint64(0), uint64(0)
							if oldRx, ok := lc.prevIfaceRx[nk]; ok && uint64(rxBytes) >= oldRx {
								rxDelta = uint64(rxBytes) - oldRx
							}
							if oldTx, ok := lc.prevIfaceTx[nk]; ok && uint64(txBytes) >= oldTx {
								txDelta = uint64(txBytes) - oldTx
							}
							lc.prevIfaceRx[nk] = uint64(rxBytes)
							lc.prevIfaceTx[nk] = uint64(txBytes)

							snap.Ifaces = append(snap.Ifaces, store.IfaceStat{
								Name:    ifaceName,
								RxBytes: rxDelta,
								TxBytes: txDelta,
								RxPkts:  uint64(rxPackets),
								TxPkts:  uint64(txPackets),
							})
						}
					}

					// Pull storage disk partitions
					for _, disk := range domXML.Devices.Disks {
						diskName := disk.Target.Dev
						if diskName == "" {
							continue
						}

						rdReq, rdBytes, wrReq, wrBytes, _, err := lc.l.DomainBlockStats(d, diskName)
						if err == nil {
							dk := prevDiskKey{domain: d.Name, disk: diskName}
							rdDelta, wrDelta := uint64(0), uint64(0)
							if oldRd, ok := lc.prevDiskRd[dk]; ok && uint64(rdBytes) >= oldRd {
								rdDelta = uint64(rdBytes) - oldRd
							}
							if oldWr, ok := lc.prevDiskWr[dk]; ok && uint64(wrBytes) >= oldWr {
								wrDelta = uint64(wrBytes) - oldWr
							}
							lc.prevDiskRd[dk] = uint64(rdBytes)
							lc.prevDiskWr[dk] = uint64(wrBytes)

							snap.Disks = append(snap.Disks, store.DiskStat{
								Dev:     diskName,
								RdBytes: rdDelta,
								WrBytes: wrDelta,
								RdReqs:  uint64(rdReq),
								WrReqs:  uint64(wrReq),
							})
						}
					}
				}
			}
		}

		s.Update(snap)
	}

	return nil
}

func (lc *LibvirtCollector) computeCpuPercentages(name string, infos []libvirt.VcpuInfo, snap *store.DomainSnapshot, now time.Time) {
	prevTimes := lc.prevCpuTime[name]
	prevTick, hasPrev := lc.prevTick[name]

	currentTimes := make([]uint64, len(infos))
	snap.VCPUs = make([]store.VCPUStat, len(infos))

	for i, info := range infos {
		currentTimes[i] = info.CPUTime
		snap.VCPUs[i] = store.VCPUStat{Index: i}

		if hasPrev && i < len(prevTimes) && now.After(prevTick) {
			deltaNs := info.CPUTime - prevTimes[i]
			wallTimeNs := uint64(now.Sub(prevTick).Nanoseconds())
			if wallTimeNs > 0 {
				snap.VCPUs[i].CPUPercent = (float64(deltaNs) / float64(wallTimeNs)) * 100.0
			}
		}
	}

	lc.prevCpuTime[name] = currentTimes
	lc.prevTick[name] = now
}

func mapDomainState(state int32) string {
	switch state {
	case 1:
		return "running"
	case 2:
		return "blocked"
	case 3:
		return "paused"
	case 4:
		return "shutdown"
	case 5:
		return "shut off"
	case 6:
		return "crashed"
	case 7:
		return "pmsuspended"
	default:
		return "unknown"
	}
}
