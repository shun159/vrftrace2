package vrft

import (
	"encoding/binary"
	"fmt"
)

type PerfEvent struct {
	PacketId      uint64
	Tstamp        uint64
	Faddr         uint64
	Fname         string
	ProcessorId   uint32
	IsReturn      uint8
}

func handleEvent(event chan []byte, sym_data *SymbolData) {
	for b := range event {
		perf := PerfEvent{}
		perf.PacketId = binary.LittleEndian.Uint64(b[0:8])
		perf.Tstamp = binary.LittleEndian.Uint64(b[8:16])
		perf.Faddr = binary.LittleEndian.Uint64(b[16:24])
		perf.ProcessorId = binary.LittleEndian.Uint32(b[24:28])
		val, err := sym_data.SymTable.GetSymbolByAddr(perf.Faddr)
		if err != nil {
			fmt.Printf("err: %v", err)
		}

		perf.Fname = val.Name
		fmt.Printf("perf: %+v\n", perf)
	}
}
