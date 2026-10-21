package api

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestRealtimeXrayPersistentCounterRPC(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "stats.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	name := "user>>>server/offline-peer>>>traffic>>>downlink"
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		if method != "/xray.app.stats.command.StatsService/QueryStats" {
			t.Errorf("wrong method: %s", method)
		}
		request := dynamicpb.NewMessage(realtimeStatsSchema.Messages().ByName("Request"))
		if err := stream.RecvMsg(request); err != nil {
			return err
		}
		fields := request.Descriptor().Fields()
		if request.Get(fields.ByName("reset")).Bool() {
			t.Error("destructive counter reset")
		}
		if request.Get(fields.ByName("pattern")).String() != "user>>>" {
			t.Error("wrong counter filter")
		}
		response := dynamicpb.NewMessage(realtimeStatsSchema.Messages().ByName("Response"))
		stats := response.Mutable(response.Descriptor().Fields().ByName("stat")).List()
		entry := stats.NewElement().Message()
		entry.Set(entry.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString(name))
		entry.Set(entry.Descriptor().Fields().ByName("value"), protoreflect.ValueOfInt64(672260))
		stats.Append(protoreflect.ValueOfMessage(entry))
		return stream.SendMsg(response)
	}))
	go server.Serve(listener)
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		counts, err := realtimeXrayCounters(ctx, socket)
		if err != nil || counts[name] != 672260 {
			t.Fatalf("persistent counter: %v %v", counts, err)
		}
	}
}
