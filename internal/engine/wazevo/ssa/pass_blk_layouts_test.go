package ssa

import (
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

func Test_maybeInvertBranch(t *testing.T) {
	insertJump := func(b *builder, src, dst *BasicBlock) {
		b.SetCurrentBlock(src)
		if src.Kind == BlockPlain && len(src.Succ) != 0 {
			panic("BUG: multiple jumps in a plain block")
		}
		src.Succ = append(src.Succ, dst)
		src.SuccArguments = append(src.SuccArguments, nil)
		dst.Pred = append(dst.Pred, src)
	}

	insertBrz := func(b *builder, src, dst *BasicBlock) {
		b.SetCurrentBlock(src)
		vinst := b.AllocateInstruction().AsIconst32(0)
		b.InsertInstruction(vinst)
		if src.Kind == BlockIfNot || src.Kind == BlockIf {
			panic("BUG: multiple conditional branches in a if block")
		}
		src.Kind = BlockIfNot
		src.Succ = append(src.Succ, dst)
		src.SuccArguments = append(src.SuccArguments, nil)
		dst.Pred = append(dst.Pred, src)
	}

	for _, tc := range []struct {
		name  string
		setup func(b *builder) (now, next *BasicBlock, verify func(t *testing.T))
		exp   bool
	}{
		{
			name: "no conditional branch without previous instruction",
			setup: func(b *builder) (now, next *BasicBlock, verify func(t *testing.T)) {
				now, next = b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, now, next)
				verify = func(t *testing.T) {
					require.Equal(t, BlockPlain, now.Kind)
				}
				return
			},
		},
		{
			name: "no conditional branch with previous instruction",
			setup: func(b *builder) (now, next *BasicBlock, verify func(t *testing.T)) {
				now, next = b.allocateBasicBlock(), b.allocateBasicBlock()
				b.SetCurrentBlock(now)
				prev := b.AllocateInstruction()
				prev.AsIconst64(1)
				b.InsertInstruction(prev)
				insertJump(b, now, next)
				verify = func(t *testing.T) {
					require.Equal(t, BlockPlain, now.Kind)
				}
				return
			},
		},
		{
			name: "tail target is already loop",
			setup: func(b *builder) (now, next *BasicBlock, verify func(t *testing.T)) {
				now, next, loopHeader, dummy := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				loopHeader.LoopHeader = true
				insertBrz(b, now, dummy)
				insertJump(b, now, loopHeader)
				verify = func(t *testing.T) {
					require.Equal(t, BlockIfNot, now.Kind) // intact.
				}
				return
			},
		},
		{
			name: "tail target is already the next block",
			setup: func(b *builder) (now, next *BasicBlock, verify func(t *testing.T)) {
				now, next, dummy := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				insertBrz(b, now, dummy)
				insertJump(b, now, next)
				verify = func(t *testing.T) {
					require.Equal(t, BlockIfNot, now.Kind) // intact.
				}
				return
			},
		},
		{
			name: "conditional target is loop",
			setup: func(b *builder) (now, next *BasicBlock, verify func(t *testing.T)) {
				now, next, loopHeader := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				loopHeader.LoopHeader = true
				insertBrz(b, now, loopHeader) // jump to loop, which needs inversion.
				insertJump(b, now, next)

				// Sanity check before inversion.
				require.Equal(t, now.Succ[0], loopHeader)
				require.Equal(t, now.Succ[1], next)
				verify = func(t *testing.T) {
					require.Equal(t, BlockIf, now.Kind)       // inversion.
					require.Equal(t, loopHeader, now.Succ[1]) // swapped.
					require.Equal(t, next, now.Succ[0])       // swapped.
				}
				return
			},
			exp: true,
		},
		{
			name: "conditional target is the next block",
			setup: func(b *builder) (now, next *BasicBlock, verify func(t *testing.T)) {
				now, next = b.allocateBasicBlock(), b.allocateBasicBlock()
				nowTarget := b.allocateBasicBlock()
				insertBrz(b, now, next) // jump to the next block in conditional, which needs inversion.
				insertJump(b, now, nowTarget)

				// Sanity check before inversion.
				require.Equal(t, now.Succ[0], next)
				require.Equal(t, now.Succ[1], nowTarget)
				verify = func(t *testing.T) {
					require.Equal(t, BlockIf, now.Kind)      // inversion.
					require.Equal(t, nowTarget, now.Succ[0]) // swapped.
					require.Equal(t, next, now.Succ[1])      // swapped.
				}
				return
			},
			exp: true,
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder().(*builder)
			now, next, verify := tc.setup(b)
			actual := maybeInvertBranches(now, next)
			verify(t)
			require.Equal(t, tc.exp, actual)
		})
	}
}

func TestBuilder_LayoutBlocks(t *testing.T) {
	insertJump := func(b *builder, src, dst *BasicBlock, vs ...Var) {
		b.SetCurrentBlock(src)
		if src.Kind == BlockPlain && len(src.Succ) != 0 {
			panic("BUG: multiple jumps in a plain block")
		}
		src.Succ = append(src.Succ, dst)
		src.SuccArguments = append(src.SuccArguments, vs)
		dst.Pred = append(dst.Pred, src)
	}

	insertIf := func(b *builder, src, dst *BasicBlock, condVal Var, vs ...Var) {
		b.SetCurrentBlock(src)
		vinst := b.AllocateInstruction().AsIconst32(0)
		b.InsertInstruction(vinst)
		if src.Kind == BlockIfNot {
			panic("BUG: multiple conditional branches in a if block")
		}
		src.Kind = BlockIfNot
		src.ControlValue = condVal
		src.Succ = append(src.Succ, dst)
		src.SuccArguments = append(src.SuccArguments, vs)
		dst.Pred = append(dst.Pred, src)
	}

	for _, tc := range []struct {
		name  string
		setup func(b *builder)
		exp   []BasicBlockID
	}{
		{
			name: "sequential - no critical edge",
			setup: func(b *builder) {
				b1, b2, b3, b4 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, b1, b2)
				insertJump(b, b2, b3)
				insertJump(b, b3, b4)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
				b.Seal(b4)
			},
			exp: []BasicBlockID{0, 1, 2, 3},
		},
		{
			name: "sequential with unreachable predecessor",
			setup: func(b *builder) {
				b0, unreachable, b2 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, b0, b2)
				insertJump(b, unreachable, b2)
				unreachable.invalid = true
				b.Seal(b0)
				b.Seal(unreachable)
				b.Seal(b2)
			},
			exp: []BasicBlockID{0, 2},
		},
		{
			name: "merge - no critical edge",
			// 0 -> 1 -> 3
			// |         ^
			// v         |
			// 2 ---------
			setup: func(b *builder) {
				b0, b1, b2, b3 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				b.SetCurrentBlock(b0)
				c := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c)
				insertIf(b, b0, b2, c.Return())
				insertJump(b, b0, b1)
				insertJump(b, b1, b3)
				insertJump(b, b2, b3)
				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
			},
			exp: []BasicBlockID{0, 2, 1, 3},
		},
		{
			name: "loop towards loop header in fallthrough",
			//    0
			//    v
			//    1<--+
			//    |   | <---- critical
			//    2---+
			//    v
			//    3
			//
			// ==>
			//
			//    0
			//    v
			//    1<---+
			//    |    |
			//    2--->4
			//    v
			//    3
			setup: func(b *builder) {
				b0, b1, b2, b3 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, b0, b1)
				insertJump(b, b1, b2)
				b.SetCurrentBlock(b2)
				c := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c)
				insertIf(b, b2, b1, c.Return())
				insertJump(b, b2, b3)
				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
			},
			// The trampoline 4 is placed right after 2, which is the hot path of the loop.
			exp: []BasicBlockID{0, 1, 2, 4, 3},
		},
		{
			name: "loop - towards loop header in conditional branch",
			//    0
			//    v
			//    1<--+
			//    |   | <---- critical
			//    2---+
			//    v
			//    3
			//
			// ==>
			//
			//    0
			//    v
			//    1<---+
			//    |    |
			//    2--->4
			//    v
			//    3
			setup: func(b *builder) {
				b0, b1, b2, b3 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, b0, b1)
				insertJump(b, b1, b2)
				b.SetCurrentBlock(b2)
				c := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c)
				insertIf(b, b2, b3, c.Return())
				insertJump(b, b2, b1)
				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
			},
			// The trampoline 4 is placed right after 2, which is the hot path of the loop.
			exp: []BasicBlockID{0, 1, 2, 4, 3},
		},
		{
			name: "loop with header is critical backward edge",
			//    0
			//    v
			//    1<--+
			//  / |   |
			// 3  2   | <--- critical
			//  \ |   |
			//    4---+
			//    v
			//    5
			//
			// ==>
			//
			//    0
			//    v
			//    1<----+
			//  / |     |
			// 3  2     |
			//  \ |     |
			//    4---->6
			//    v
			//    5
			setup: func(b *builder) {
				b0, b1, b2, b3, b4, b5 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(),
					b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, b0, b1)
				b.SetCurrentBlock(b0)
				c1 := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c1)
				insertIf(b, b1, b2, c1.Return())
				insertJump(b, b1, b3)
				insertJump(b, b3, b4)
				insertJump(b, b2, b4)
				b.SetCurrentBlock(b4)
				c2 := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c2)
				insertIf(b, b4, b1, c2.Return())
				insertJump(b, b4, b5)
				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
				b.Seal(b4)
				b.Seal(b5)
			},
			// The trampoline 6 is placed right after 4, which is the hot path of the loop.
			exp: []BasicBlockID{0, 1, 2, 3, 4, 6, 5},
		},
		{
			name: "multiple critical edges",
			//                   0
			//                   v
			//               +---1<--+
			//               |   v   | <---- critical
			// critical ---->|   2 --+
			//               |   | <-------- critical
			//               |   v
			//               +-->3--->4
			//
			// ==>
			//
			//                   0
			//                   v
			//               +---1<---+
			//               |   v    |
			//               5   2 -->6
			//               |   v
			//               |   7
			//               |   v
			//               +-->3--->4
			setup: func(b *builder) {
				b0, b1, b2, b3, b4 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(),
					b.allocateBasicBlock(), b.allocateBasicBlock()
				insertJump(b, b0, b1)
				b.SetCurrentBlock(b1)
				c1 := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c1)
				insertIf(b, b1, b2, c1.Return())
				insertJump(b, b1, b3)

				b.SetCurrentBlock(b2)
				c2 := b.AllocateInstruction().AsIconst32(0)
				b.InsertInstruction(c2)
				insertIf(b, b2, b1, c2.Return())
				insertJump(b, b2, b3)
				insertJump(b, b3, b4)

				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
				b.Seal(b4)
			},
			exp: []BasicBlockID{
				0, 1,
				// block 2 has loop header (1) as the conditional branch target, so it's inverted,
				// and the split edge trampoline is placed right after 2 which is the hot path of the loop.
				2, 7, 5,
				// Then the placement iteration goes to 3, which has two (5, 7) unplaced trampolines as predecessors,
				// so they are placed before 3.
				6, 3,
				// Then the final block.
				4,
			},
		},
		{
			name: "brz with arg",
			setup: func(b *builder) {
				b0, b1, b2 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()
				p := b0.AddParam(b, types.I32)
				retval := b1.AddParam(b, types.I32)

				b.SetCurrentBlock(b0)
				{
					arg := b.AllocateInstruction().AsIconst32(1000).Insert(b).Return()
					insertIf(b, b0, b1, p, arg)
					insertJump(b, b0, b2)
				}
				b.SetCurrentBlock(b1)
				{
					args := []Var{retval}
					b.AllocateInstruction().AsReturn(args).Insert(b)
				}
				b.SetCurrentBlock(b2)
				{
					arg := b.AllocateInstruction().AsIconst32(1).Insert(b).Return()
					insertJump(b, b2, b1, arg)
				}

				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
			},
			exp: []BasicBlockID{0x0, 0x3, 0x1, 0x2},
		},
		{
			name: "loop with output",
			exp:  []BasicBlockID{0x0, 0x2, 0x4, 0x1, 0x3, 0x5, 0x6},
			setup: func(b *builder) {
				b.currentSignature = &types.Signature{Results: []*types.Type{types.I32}}
				b0, b1, b2, b3 := b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock(), b.allocateBasicBlock()

				b.SetCurrentBlock(b0)
				funcParam := b0.AddParam(b, types.I32)
				b2Param := b2.AddParam(b, types.I32)
				insertJump(b, b0, b2, funcParam)

				b.SetCurrentBlock(b1)
				{
					returnParam := b1.AddParam(b, types.I32)
					insertJump(b, b1, b.returnBlk, returnParam)
				}

				b.SetCurrentBlock(b2)
				{
					c := b.AllocateInstruction().AsIconst32(100).Insert(b)
					cmp := b.AllocateInstruction().
						AsIcmp(b2Param, c.Return(), IntegerCmpCondUnsignedLessThan).
						Insert(b)
					insertIf(b, b2, b1, cmp.Return(), b2Param)
					insertJump(b, b2, b3)
				}

				b.SetCurrentBlock(b3)
				{
					one := b.AllocateInstruction().AsIconst32(1).Insert(b)
					minusOned := b.AllocateInstruction().AsIsub(b2Param, one.Return()).Insert(b)
					c := b.AllocateInstruction().AsIconst32(150).Insert(b)
					cmp := b.AllocateInstruction().
						AsIcmp(b2Param, c.Return(), IntegerCmpCondEqual).
						Insert(b)
					insertIf(b, b3, b1, cmp.Return(), minusOned.Return())
					insertJump(b, b3, b2, minusOned.Return())
				}

				b.Seal(b0)
				b.Seal(b1)
				b.Seal(b2)
				b.Seal(b3)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder().(*builder)
			tc.setup(b)

			for _, p := range passes {
				p.fn(b)
				if b.doneBlockLayout {
					break
				}
			}

			var actual []BasicBlockID
			for blk := b.BlockIteratorReversePostOrderBegin(); blk != nil; blk = b.BlockIteratorReversePostOrderNext() {
				actual = append(actual, blk.id)
			}
			require.Equal(t, tc.exp, actual)
		})
	}
}
