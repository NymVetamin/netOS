package wifi

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Linux wireless-regdb firmware format v20 (net/wireless/reg.c).
// Reading it is advisory; cfg80211 still enforces signed regulatory rules.
type regRule struct {
	start, end, width int
	power             float64
	flags             byte
}
type regulatoryDB map[string][]regRule

func readRegDB() (regulatoryDB, error) {
	data, err := os.ReadFile("/lib/firmware/regulatory.db")
	if err != nil {
		return nil, fmt.Errorf("база стран Wi-Fi недоступна: %w", err)
	}
	return parseRegDB(data)
}

func parseRegDB(data []byte) (regulatoryDB, error) {
	bad := fmt.Errorf("повреждённая или неподдерживаемая regulatory.db")
	if len(data) < 12 || string(data[:4]) != "RGDB" || binary.BigEndian.Uint32(data[4:8]) != 20 {
		return nil, bad
	}
	db := regulatoryDB{}
	for at := 8; at+4 <= len(data); at += 4 {
		ptr := int(binary.BigEndian.Uint16(data[at+2:at+4])) * 4
		if ptr == 0 {
			return db, nil
		}
		if ptr+3 > len(data) || data[ptr] < 3 {
			return nil, bad
		}
		n := int(data[ptr+1])
		list := ptr + (int(data[ptr])+1)&^1
		if list+n*2 > len(data) {
			return nil, bad
		}
		country := string(data[at : at+2])
		for i := 0; i < n; i++ {
			p := int(binary.BigEndian.Uint16(data[list+2*i:list+2*i+2])) * 4
			if p+16 > len(data) || data[p] < 16 || p+int(data[p]) > len(data) {
				return nil, bad
			}
			r := regRule{int(binary.BigEndian.Uint32(data[p+4:p+8])) / 1000, int(binary.BigEndian.Uint32(data[p+8:p+12])) / 1000, int(binary.BigEndian.Uint32(data[p+12:p+16])) / 1000, float64(binary.BigEndian.Uint16(data[p+2:p+4])) / 100, data[p+1]}
			if r.start >= r.end || r.width <= 0 {
				return nil, bad
			}
			db[country] = append(db[country], r)
		}
	}
	return nil, bad
}

func (db regulatoryDB) limit(country string, center, width int) (float64, bool) {
	for _, r := range db[country] {
		// NO-OFDM and NO-IR cannot provide our HT/VHT access point.
		if r.flags&9 == 0 && center-width/2 >= r.start && center+width/2 <= r.end && width <= r.width {
			return r.power, true
		}
	}
	return 0, false
}
