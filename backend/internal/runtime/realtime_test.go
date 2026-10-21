package runtime

import "testing"

func TestRealtimeInterfaceByteColumns(t *testing.T) {
	rows := ParseInterfaceCounters(`Inter-| Receive | Transmit
 eth0: 12345 999 0 0 0 0 0 0 67890 888 0 0 0 0 0 0
 lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0
 broken: invalid 0 0 0 0 0 0 0 100 1 0 0 0 0 0 0
 short: 1 2`)
	if len(rows) != 1 || rows["eth0"].RX != 12345 || rows["eth0"].TX != 67890 {
		t.Fatal(rows)
	}
}
