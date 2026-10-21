package api

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Wire schema from Xray v26.7.28 app/stats/command/command.proto.
// QueryStats includes cumulative counters even after a connection has closed;
// GetUsersStats omits offline users and can miss sub-second transfers entirely.
var realtimeStatsSchema = func() protoreflect.FileDescriptor {
	field := func(name string, number int32, kind descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(number), Type: kind.Enum()}
	}
	entries := field("stat", 1, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE)
	entries.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	entries.TypeName = proto.String(".netos.realtime.Stat")
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("netos-realtime-stats.proto"), Package: proto.String("netos.realtime"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Stat"), Field: []*descriptorpb.FieldDescriptorProto{field("name", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING), field("value", 2, descriptorpb.FieldDescriptorProto_TYPE_INT64)}},
			{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{field("pattern", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING), field("reset", 2, descriptorpb.FieldDescriptorProto_TYPE_BOOL)}},
			{Name: proto.String("Response"), Field: []*descriptorpb.FieldDescriptorProto{entries}},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return file
}()

func realtimeXrayCounters(ctx context.Context, socket string) (map[string]uint64, error) {
	conn, err := grpc.DialContext(ctx, "unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	request := dynamicpb.NewMessage(realtimeStatsSchema.Messages().ByName("Request"))
	request.Set(request.Descriptor().Fields().ByName("pattern"), protoreflect.ValueOfString("user>>>"))
	response := dynamicpb.NewMessage(realtimeStatsSchema.Messages().ByName("Response"))
	// reset remains false; the history sampler owns its own counter baseline.
	if err = conn.Invoke(ctx, "/xray.app.stats.command.StatsService/QueryStats", request, response); err != nil {
		return nil, err
	}
	result := map[string]uint64{}
	entries := response.Get(response.Descriptor().Fields().ByName("stat")).List()
	for i := 0; i < entries.Len(); i++ {
		entry := entries.Get(i).Message()
		name := entry.Get(entry.Descriptor().Fields().ByName("name")).String()
		value := entry.Get(entry.Descriptor().Fields().ByName("value")).Int()
		if value >= 0 {
			result[name] = uint64(value)
		}
	}
	return result, nil
}
