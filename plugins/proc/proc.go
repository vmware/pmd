// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package proc

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/web"
)

const (
	procMiscPath    = "/proc/misc"
	procNetArpPath  = "/proc/net/arp"
	procModulesPath = "/proc/modules"
)

type NetARP struct {
	IPAddress string `json:"IPAddress"`
	HWType    string `json:"HWType"`
	Flags     string `json:"Flags"`
	HWAddress string `json:"HWAddress"`
	Mask      string `json:"Mask"`
	Device    string `json:"Device"`
}

type Modules struct {
	Module     string `json:"Module"`
	MemorySize string `json:"MemorySize"`
	Instances  string `json:"Instances"`
	Dependent  string `json:"Dependent"`
	State      string `json:"State"`
}

func AcquireHostInfo(ctx context.Context, w http.ResponseWriter) error {
	infoStat, err := host.InfoWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(infoStat, w)
}

func AcquirePlatformInformation(ctx context.Context, w http.ResponseWriter) error {
	platform, family, version, err := host.PlatformInformation()
	if err != nil {
		return err
	}

	p := struct {
		Platform string
		Family   string
		Version  string
	}{
		platform,
		family,
		version,
	}

	return web.JSONResponse(p, w)
}

func AcquireVirtualization(ctx context.Context, w http.ResponseWriter) error {
	system, role, err := host.VirtualizationWithContext(ctx)
	if err != nil {
		return err
	}

	v := struct {
		System string
		Role   string
	}{
		system,
		role,
	}

	return web.JSONResponse(v, w)
}

func AcquireUserStat(ctx context.Context, w http.ResponseWriter) error {
	userStat, err := host.UsersWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(userStat, w)
}

func AcquireTemperatureStat(ctx context.Context, w http.ResponseWriter) error {
	tempStat, err := host.SensorsTemperaturesWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(tempStat, w)
}

// read netstat from proc tcp/udp/sctp
func AcquireNetStat(ctx context.Context, w http.ResponseWriter, protocol string) error {
	conn, err := net.ConnectionsWithContext(ctx, protocol)
	if err != nil {
		return err
	}

	return web.JSONResponse(conn, w)
}

func AcquireNetStatPid(ctx context.Context, w http.ResponseWriter, protocol string, process string) error {
	pid, err := strconv.ParseInt(process, 10, 32)
	if err != nil || protocol == "" || pid == 0 {
		return errors.New("can't parse request")
	}

	conn, err := net.ConnectionsPidWithContext(ctx, protocol, int32(pid))
	if err != nil {
		return err
	}

	return web.JSONResponse(conn, w)
}

func AcquireProtoCountersStat(ctx context.Context, w http.ResponseWriter) error {
	protocols := []string{"ip", "icmp", "icmpmsg", "tcp", "udp", "udplite"}

	proto, err := net.ProtoCountersWithContext(ctx, protocols)
	if err != nil {
		return err
	}

	return web.JSONResponse(proto, w)
}

func AcquireNetDevIOCounters(ctx context.Context, w http.ResponseWriter) error {
	netDev, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return err
	}

	return web.JSONResponse(netDev, w)
}

func AcquireInterfaces(ctx context.Context, w http.ResponseWriter) error {
	interfaces, err := net.InterfacesWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(interfaces, w)
}

func AcquireVirtualMemoryStat(ctx context.Context, w http.ResponseWriter) error {
	m, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(m, w)
}

func AcquireCPUInfo(ctx context.Context, w http.ResponseWriter) error {
	cpuInfo, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(cpuInfo, w)
}

func AcquireCPUTimeStat(ctx context.Context, w http.ResponseWriter) error {
	cpuTime, err := cpu.TimesWithContext(ctx, true)
	if err != nil {
		return err
	}

	return web.JSONResponse(cpuTime, w)
}

func AcquireAvgStat(ctx context.Context, w http.ResponseWriter) error {
	avgStat, err := load.AvgWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(avgStat, w)
}

func AcquireDiskPartitions(ctx context.Context, w http.ResponseWriter) error {
	part, err := disk.Partitions(true)
	if err != nil {
		return err
	}

	return web.JSONResponse(part, w)
}

func AcquireIOCounters(ctx context.Context, w http.ResponseWriter) error {
	ioCounters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return err
	}

	return web.JSONResponse(ioCounters, w)
}

func AcquireDiskUsage(ctx context.Context, w http.ResponseWriter) error {
	u, err := disk.UsageWithContext(ctx, "/")
	if err != nil {
		return err
	}

	return web.JSONResponse(u, w)
}

func AcquireMisc(ctx context.Context, w http.ResponseWriter) error {
	lines, err := system.ReadFullFile(procMiscPath)
	if err != nil {
		log.Fatalf("Failed to read: %s", procMiscPath)
		return err
	}

	miscMap := make(map[int]string)
	for _, line := range lines {
		fields := strings.Fields(line)

		deviceNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		miscMap[deviceNum] = fields[1]
	}

	return web.JSONResponse(miscMap, w)
}

func AcquireNetArp(ctx context.Context, w http.ResponseWriter) error {
	lines, err := system.ReadFullFile(procNetArpPath)
	if err != nil {
		log.Errorf("Failed to read '%s': %v", procNetArpPath, err)
		return err
	}

	arp := make([]NetARP, len(lines))
	for i, line := range lines {
		if i == 0 {
			continue
		}

		fields := strings.Fields(line)
		arp[i] = NetARP{
			IPAddress: fields[0],
			HWType:    fields[1],
			Flags:     fields[2],
			HWAddress: fields[3],
			Mask:      fields[4],
			Device:    fields[5],
		}
	}

	return web.JSONResponse(arp, w)
}

func AcquireModules(ctx context.Context, w http.ResponseWriter) error {
	lines, err := system.ReadFullFile(procModulesPath)
	if err != nil {
		log.Fatalf("Failed to read '%s': %v", procModulesPath, err)
		return err
	}

	modules := make([]Modules, len(lines))
	for i, line := range lines {
		fields := strings.Fields(line)

		module := Modules{}

		for j, field := range fields {
			switch j {
			case 0:
				module.Module = field

			case 1:
				module.MemorySize = field

			case 2:
				module.Instances = field

			case 3:
				module.Dependent = field

			case 4:
				module.State = field
			}
		}

		modules[i] = module
	}

	return web.JSONResponse(modules, w)
}

func AcquireProcessInfo(ctx context.Context, w http.ResponseWriter, proc string, property string) error {
	pid, err := strconv.ParseInt(proc, 10, 32)
	if err != nil {
		return err
	}

	p, err := process.NewProcessWithContext(ctx, int32(pid))
	if err != nil {
		return err
	}

	switch property {
	case "pid-connections":
		conn, err := p.ConnectionsWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(conn, w)

	case "pid-rlimit":
		rlimit, err := p.RlimitWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(rlimit, w)

	case "pid-rlimit-usage":
		rlimit, err := p.RlimitUsageWithContext(ctx, true)
		if err != nil {
			return err
		}

		return web.JSONResponse(rlimit, w)

	case "pid-status":
		s, err := p.StatusWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(s, w)

	case "pid-username":
		u, err := p.UsernameWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(u, w)

	case "pid-open-files":
		f, err := p.OpenFilesWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(f, w)

	case "pid-fds":
		f, err := p.NumFDsWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(f, w)

	case "pid-name":
		n, err := p.NameWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(n, w)

	case "pid-memory-percent":
		m, err := p.MemoryPercentWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(m, w)

	case "pid-memory-maps":
		m, err := p.MemoryMapsWithContext(ctx, true)
		if err != nil {
			return err
		}

		return web.JSONResponse(m, w)

	case "pid-memory-info":
		m, err := p.MemoryInfoWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(m, w)

	case "pid-io-counters":
		m, err := p.IOCountersWithContext(ctx)
		if err != nil {
			return err
		}

		return web.JSONResponse(m, w)
	}

	return nil
}
