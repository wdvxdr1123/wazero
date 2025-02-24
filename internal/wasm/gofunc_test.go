package internalwasm

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	publicwasm "github.com/tetratelabs/wazero/wasm"
)

type errno uint32

func TestGetFunctionType(t *testing.T) {
	i32, i64, f32, f64 := ValueTypeI32, ValueTypeI64, ValueTypeF32, ValueTypeF64

	tests := []struct {
		name              string
		inputFunc         interface{}
		allowErrorResult  bool
		expectedKind      FunctionKind
		expectedType      *FunctionType
		expectErrorResult bool
	}{
		{
			name:         "nullary",
			inputFunc:    func() {},
			expectedKind: FunctionKindGoNoContext,
			expectedType: &FunctionType{Params: []ValueType{}, Results: []ValueType{}},
		},
		{
			name:             "nullary allowErrorResult",
			inputFunc:        func() {},
			allowErrorResult: true,
			expectedKind:     FunctionKindGoNoContext,
			expectedType:     &FunctionType{Params: []ValueType{}, Results: []ValueType{}},
		},
		{
			name:              "void error result",
			inputFunc:         func() error { return nil },
			allowErrorResult:  true,
			expectedKind:      FunctionKindGoNoContext,
			expectErrorResult: true,
			expectedType:      &FunctionType{Params: []ValueType{}, Results: []ValueType{}},
		},
		{
			name:             "void uint32 allowErrorResult",
			inputFunc:        func() uint32 { return 0 },
			allowErrorResult: true,
			expectedKind:     FunctionKindGoNoContext,
			expectedType:     &FunctionType{Params: []ValueType{}, Results: []ValueType{i32}},
		},
		{
			name:             "void type uint32 allowErrorResult",
			inputFunc:        func() errno { return 0 },
			allowErrorResult: true,
			expectedKind:     FunctionKindGoNoContext,
			expectedType:     &FunctionType{Params: []ValueType{}, Results: []ValueType{i32}},
		},
		{
			name:              "void (uint32,error) results",
			inputFunc:         func() (uint32, error) { return 0, nil },
			allowErrorResult:  true,
			expectedKind:      FunctionKindGoNoContext,
			expectErrorResult: true,
			expectedType:      &FunctionType{Params: []ValueType{}, Results: []ValueType{i32}},
		},
		{
			name:         "wasm.ModuleContext void return",
			inputFunc:    func(publicwasm.ModuleContext) {},
			expectedKind: FunctionKindGoModuleContext,
			expectedType: &FunctionType{Params: []ValueType{}, Results: []ValueType{}},
		},
		{
			name:         "context.Context void return",
			inputFunc:    func(context.Context) {},
			expectedKind: FunctionKindGoContext,
			expectedType: &FunctionType{Params: []ValueType{}, Results: []ValueType{}},
		},
		{
			name:         "all supported params and i32 result",
			inputFunc:    func(uint32, uint64, float32, float64) uint32 { return 0 },
			expectedKind: FunctionKindGoNoContext,
			expectedType: &FunctionType{Params: []ValueType{i32, i64, f32, f64}, Results: []ValueType{i32}},
		},
		{
			name:         "all supported params and i32 result - wasm.ModuleContext",
			inputFunc:    func(publicwasm.ModuleContext, uint32, uint64, float32, float64) uint32 { return 0 },
			expectedKind: FunctionKindGoModuleContext,
			expectedType: &FunctionType{Params: []ValueType{i32, i64, f32, f64}, Results: []ValueType{i32}},
		},
		{
			name:         "all supported params and i32 result - context.Context",
			inputFunc:    func(context.Context, uint32, uint64, float32, float64) uint32 { return 0 },
			expectedKind: FunctionKindGoContext,
			expectedType: &FunctionType{Params: []ValueType{i32, i64, f32, f64}, Results: []ValueType{i32}},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			rVal := reflect.ValueOf(tc.inputFunc)
			fk, ft, hasErrorResult, err := GetFunctionType("fn", &rVal, tc.allowErrorResult)
			require.NoError(t, err)
			require.Equal(t, tc.expectedKind, fk)
			require.Equal(t, tc.expectedType, ft)
			require.Equal(t, tc.expectErrorResult, hasErrorResult)
		})
	}
}

func TestGetFunctionTypeErrors(t *testing.T) {
	tests := []struct {
		name             string
		input            interface{}
		allowErrorResult bool
		expectedErr      string
	}{
		{
			name:        "not a func",
			input:       struct{}{},
			expectedErr: "fn is a struct, but should be a Func",
		},
		{
			name:        "unsupported param",
			input:       func(uint32, string) {},
			expectedErr: "fn param[1] is unsupported: string",
		},
		{
			name:        "unsupported result",
			input:       func() string { return "" },
			expectedErr: "fn result[0] is unsupported: string",
		},
		{
			name:        "error result",
			input:       func() error { return nil },
			expectedErr: "fn result[0] is an error, which is unsupported",
		},
		{
			name:        "multiple results",
			input:       func() (uint64, uint32) { return 0, 0 },
			expectedErr: "fn has more than one result",
		},
		{
			name:        "multiple context types",
			input:       func(publicwasm.ModuleContext, context.Context) error { return nil },
			expectedErr: "fn param[1] is a context.Context, which may be defined only once as param[0]",
		},
		{
			name:        "multiple context.Context",
			input:       func(context.Context, uint64, context.Context) error { return nil },
			expectedErr: "fn param[2] is a context.Context, which may be defined only once as param[0]",
		},
		{
			name:        "multiple wasm.ModuleContext",
			input:       func(publicwasm.ModuleContext, uint64, publicwasm.ModuleContext) error { return nil },
			expectedErr: "fn param[2] is a wasm.ModuleContext, which may be defined only once as param[0]",
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			rVal := reflect.ValueOf(tc.input)
			_, _, _, err := GetFunctionType("fn", &rVal, tc.allowErrorResult)
			require.EqualError(t, err, tc.expectedErr)
		})
	}
}
