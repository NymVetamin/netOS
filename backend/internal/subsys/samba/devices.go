package samba

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

type Device struct {
	Path        string      `json:"path"`
	UUID        string      `json:"uuid"`
	Label       string      `json:"label"`
	Filesystem  string      `json:"fstype"`
	Size        json.Number `json:"size"`
	Transport   string      `json:"tran"`
	Type        string      `json:"type"`
	Mountpoints []string    `json:"mountpoints"`
	Children    []Device    `json:"children,omitempty"`
	Available   bool        `json:"available"`
	Reason      string      `json:"reason,omitempty"`
}

func Devices(ctx context.Context, r system.Runner) ([]Device, error) {
	out, err := r.Run(ctx, "lsblk", "--json", "--bytes", "--output", "PATH,UUID,LABEL,FSTYPE,SIZE,TRAN,TYPE,MOUNTPOINTS")
	if err != nil {
		return nil, err
	}
	return ParseDevices([]byte(out))
}
func ParseDevices(data []byte) ([]Device, error) {
	var tree struct {
		Devices []Device `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("список дисков: %w", err)
	}
	out := []Device{}
	var flatten func([]Device, string)
	flatten = func(devices []Device, transport string) {
		for _, d := range devices {
			if d.Transport == "" {
				d.Transport = transport
			}
			flatten(d.Children, d.Transport)
			if d.UUID == "" {
				continue
			}
			d.Children = nil
			d.Available = true
			switch d.Filesystem {
			case "ext4", "ext3", "ext2", "vfat", "exfat", "ntfs":
			default:
				d.Available = false
				d.Reason = "Неподдерживаемая файловая система"
			}
			if d.Type != "part" && d.Type != "disk" {
				d.Available = false
				d.Reason = "Нужен обычный раздел или диск"
			}
			for _, m := range d.Mountpoints {
				if m != "" && !strings.HasPrefix(m, "/srv/netos/") {
					d.Available = false
					d.Reason = "Том уже используется системой: " + m
				}
			}
			out = append(out, d)
		}
	}
	flatten(tree.Devices, "")
	counts := map[string]int{}
	for _, d := range out {
		counts[strings.ToLower(d.UUID)]++
	}
	for i := range out {
		if counts[strings.ToLower(out[i].UUID)] > 1 {
			out[i].Available = false
			out[i].Reason = "UUID повторяется на нескольких устройствах"
		}
	}
	return out, nil
}
