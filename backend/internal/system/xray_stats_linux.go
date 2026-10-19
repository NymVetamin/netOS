//go:build linux

package system

import (
	"context"
	"time"

	"github.com/netos-router/netos/internal/system/xraystats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

const xrayUsersStatsMethod = "/xray.app.stats.command.StatsService/GetUsersStats"

func (e *Exec) XrayUserStats(ctx context.Context, socket string) (string, error) {
	timeout := 3 * time.Second
	if e.Timeout > 0 && e.Timeout < timeout {
		timeout = e.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Match the CLI's blocking dial and deadline. A fresh Unix connection on
	// every sample also detects a removed/replaced socket, rather than keeping
	// a stale daemon reachable through a previously established connection.
	conn, err := grpc.DialContext(ctx, "unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return "", err
	}
	defer conn.Close()
	response := new(xraystats.GetUsersStatsResponse)
	// Never reset counters: history and live rates depend on cumulative bytes.
	err = conn.Invoke(ctx, xrayUsersStatsMethod, &xraystats.GetUsersStatsRequest{IncludeTraffic: true}, response)
	if err != nil {
		return "", err
	}
	data, err := protojson.Marshal(response)
	return string(data), err
}
