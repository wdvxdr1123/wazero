package backend

import (
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

func Test_goFunctionCallRequiredStackSize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sig      *types.Signature
		argBegin int
		exp      int64
	}{
		{
			name: "no param",
			sig:  &types.Signature{},
			exp:  0,
		},
		{
			name: "only param",
			sig:  &types.Signature{Params: []types.Type{types.I64, types.V128}},
			exp:  32,
		},
		{
			name: "only result",
			sig:  &types.Signature{Results: []types.Type{types.I64, types.V128, types.I32}},
			exp:  32,
		},
		{
			name: "param < result",
			sig:  &types.Signature{Params: []types.Type{types.I64, types.V128}, Results: []types.Type{types.I64, types.V128, types.I32}},
			exp:  32,
		},
		{
			name: "param > result",
			sig:  &types.Signature{Params: []types.Type{types.I64, types.V128, types.I32}, Results: []types.Type{types.I64, types.V128}},
			exp:  32,
		},
		{
			name:     "param < result / argBegin=2",
			argBegin: 2,
			sig:      &types.Signature{Params: []types.Type{types.I64, types.V128, types.I32}, Results: []types.Type{types.I64, types.F64}},
			exp:      16,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			requiredSize, _ := GoFunctionCallRequiredStackSize(tc.sig, tc.argBegin)
			require.Equal(t, tc.exp, requiredSize)
		})
	}
}
