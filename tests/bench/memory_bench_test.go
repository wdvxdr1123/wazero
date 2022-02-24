package bench

import (
	"encoding/binary"
	"fmt"
	"testing"

	wasm "github.com/tetratelabs/wazero/internal/wasm"
	publicwasm "github.com/tetratelabs/wazero/wasm"
)

func BenchmarkMemory(b *testing.B) {
	for n, m := range map[string]publicwasm.Memory{
		"MemoryInstance": &wasm.MemoryInstance{Buffer: make([]byte, pageSize), Min: 1},
		"arrayPage":      &arrayPage{},
		"slicePage":      &slicePage{make([]byte, pageSize)},
	} {
		if !m.WriteByte(10, 16) {
			b.Fail()
		}
		if v, ok := m.ReadByte(10); !ok || v != 16 {
			b.Fail()
		}

		b.Run(fmt.Sprintf("%s.ReadByte", n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if v, ok := m.ReadByte(10); !ok || v != 16 {
					b.Fail()
				}
			}
		})

		b.Run(fmt.Sprintf("%s.ReadUint32Le", n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if v, ok := m.ReadUint32Le(10); !ok || v != 16 {
					b.Fail()
				}
			}
		})

		b.Run(fmt.Sprintf("%s.WriteByte", n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !m.WriteByte(10, 16) {
					b.Fail()
				}
			}
		})

		b.Run(fmt.Sprintf("%s.WriteUint32Le", n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !m.WriteUint32Le(10, 16) {
					b.Fail()
				}
			}
		})
	}
}

var _ publicwasm.Memory = &arrayPage{}

const pageSize = 1 << 16

type arrayPage struct {
	buf [pageSize]byte
}

func (p *arrayPage) Size() uint32 {
	return pageSize
}

func (p *arrayPage) ReadByte(offset uint32) (byte, bool) {
	if offset >= pageSize {
		return 0, false
	}
	return p.buf[offset], true
}

func (p *arrayPage) ReadUint32Le(offset uint32) (uint32, bool) {
	if offset+4 >= pageSize {
		return 0, false
	}
	buf := p.buf
	ret := uint32(buf[offset]) |
		uint32(buf[offset+1])<<8 |
		uint32(buf[offset+2])<<16 |
		uint32(buf[offset+3])<<24
	return ret, true
}

func (p *arrayPage) ReadFloat32Le(offset uint32) (float32, bool) {
	panic("implement me")
}

func (p *arrayPage) ReadUint64Le(offset uint32) (uint64, bool) {
	panic("implement me")
}

func (p *arrayPage) ReadFloat64Le(offset uint32) (float64, bool) {
	panic("implement me")
}

func (p *arrayPage) Read(offset, byteCount uint32) ([]byte, bool) {
	panic("implement me")
}

func (p *arrayPage) WriteByte(offset uint32, v byte) bool {
	if offset >= pageSize {
		return false
	}
	p.buf[offset] = v
	return true
}

func (p *arrayPage) WriteUint32Le(offset, v uint32) bool {
	if offset+4 >= pageSize {
		return false
	}
	buf := p.buf
	buf[offset+0] = byte(v)
	buf[offset+1] = byte(v >> 8)
	buf[offset+2] = byte(v >> 16)
	buf[offset+3] = byte(v >> 24)
	return true
}

func (p *arrayPage) WriteFloat32Le(offset uint32, v float32) bool {
	panic("implement me")
}

func (p *arrayPage) WriteUint64Le(offset uint32, v uint64) bool {
	panic("implement me")
}

func (p *arrayPage) WriteFloat64Le(offset uint32, v float64) bool {
	panic("implement me")
}

func (p *arrayPage) Write(offset uint32, v []byte) bool {
	panic("implement me")
}

type slicePage struct {
	buf []byte
}

func (p *slicePage) Size() uint32 {
	return pageSize
}

func (p *slicePage) ReadByte(offset uint32) (byte, bool) {
	if offset >= pageSize {
		return 0, false
	}
	return p.buf[offset], true
}

func (p *slicePage) ReadUint32Le(offset uint32) (uint32, bool) {
	if offset+4 >= pageSize {
		return 0, false
	}
	return binary.LittleEndian.Uint32(p.buf[offset:]), true
}

func (p *slicePage) ReadFloat32Le(offset uint32) (float32, bool) {
	panic("implement me")
}

func (p *slicePage) ReadUint64Le(offset uint32) (uint64, bool) {
	panic("implement me")
}

func (p *slicePage) ReadFloat64Le(offset uint32) (float64, bool) {
	panic("implement me")
}

func (p *slicePage) Read(offset, byteCount uint32) ([]byte, bool) {
	panic("implement me")
}

func (p *slicePage) WriteByte(offset uint32, v byte) bool {
	if offset >= pageSize {
		return false
	}
	p.buf[offset] = v
	return true
}

func (p *slicePage) WriteUint32Le(offset, v uint32) bool {
	if offset+4 >= pageSize {
		return false
	}
	binary.LittleEndian.PutUint32(p.buf[offset:], v)
	return true
}

func (p *slicePage) WriteFloat32Le(offset uint32, v float32) bool {
	panic("implement me")
}

func (p *slicePage) WriteUint64Le(offset uint32, v uint64) bool {
	panic("implement me")
}

func (p *slicePage) WriteFloat64Le(offset uint32, v float64) bool {
	panic("implement me")
}

func (p *slicePage) Write(offset uint32, v []byte) bool {
	panic("implement me")
}
