package types

// VecLane represents a lane in a SIMD vector.
type VecLane byte

const (
	VecLaneInvalid VecLane = 1 + iota
	VecLaneI8x16
	VecLaneI16x8
	VecLaneI32x4
	VecLaneI64x2
	VecLaneF32x4
	VecLaneF64x2
)

// String implements fmt.Stringer.
func (vl VecLane) String() (ret string) {
	switch vl {
	case VecLaneInvalid:
		return "invalid"
	case VecLaneI8x16:
		return "i8x16"
	case VecLaneI16x8:
		return "i16x8"
	case VecLaneI32x4:
		return "i32x4"
	case VecLaneI64x2:
		return "i64x2"
	case VecLaneF32x4:
		return "f32x4"
	case VecLaneF64x2:
		return "f64x2"
	default:
		panic(int(vl))
	}
}
