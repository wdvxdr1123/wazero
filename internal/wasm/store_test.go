package internalwasm

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tetratelabs/wazero/wasm"
)

func TestModuleInstance_Memory(t *testing.T) {
	tests := []struct {
		name        string
		input       *Module
		expected    bool
		expectedLen uint32
	}{
		{
			name:  "no memory",
			input: &Module{},
		},
		{
			name:  "memory not exported",
			input: &Module{MemorySection: []*MemoryType{{1, nil}}},
		},
		{
			name:  "memory not exported, one page",
			input: &Module{MemorySection: []*MemoryType{{1, nil}}},
		},
		{
			name: "memory exported, different name",
			input: &Module{
				MemorySection: []*MemoryType{{1, nil}},
				ExportSection: map[string]*Export{"momory": {Type: ExternTypeMemory, Name: "momory", Index: 0}},
			},
		},
		{
			name: "memory exported, but zero length",
			input: &Module{
				MemorySection: []*MemoryType{{0, nil}},
				ExportSection: map[string]*Export{"memory": {Type: ExternTypeMemory, Name: "memory", Index: 0}},
			},
			expected: true,
		},
		{
			name: "memory exported, one page",
			input: &Module{
				MemorySection: []*MemoryType{{1, nil}},
				ExportSection: map[string]*Export{"memory": {Type: ExternTypeMemory, Name: "memory", Index: 0}},
			},
			expected:    true,
			expectedLen: 65536,
		},
		{
			name: "memory exported, two pages",
			input: &Module{
				MemorySection: []*MemoryType{{2, nil}},
				ExportSection: map[string]*Export{"memory": {Type: ExternTypeMemory, Name: "memory", Index: 0}},
			},
			expected:    true,
			expectedLen: 65536 * 2,
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})

			instance, err := s.Instantiate(tc.input, "test")
			require.NoError(t, err)

			mem := instance.Memory("memory")
			if tc.expected {
				require.Equal(t, tc.expectedLen, mem.Size())
			} else {
				require.Nil(t, mem)
			}
		})
	}
}

func TestStore_AddHostFunction(t *testing.T) {
	s := NewStore(context.Background(), &catchContext{})

	hf, err := NewGoFunc("fn", func(wasm.ModuleContext) {
	})
	require.NoError(t, err)

	// Add the host module
	hostModule := &ModuleInstance{Name: "test", Exports: make(map[string]*ExportInstance, 1)}
	s.ModuleInstances[hostModule.Name] = hostModule

	_, err = s.AddHostFunction(hostModule, hf)
	require.NoError(t, err)

	// The function was added to the store, prefixed by the owning module name
	require.Equal(t, 1, len(s.Functions))
	fn := s.Functions[0]
	require.Equal(t, "test.fn", fn.Name)

	// The function was exported in the module
	require.Equal(t, 1, len(hostModule.Exports))
	exp, ok := hostModule.Exports["fn"]
	require.True(t, ok)

	// Trying to register it again should fail
	_, err = s.AddHostFunction(hostModule, hf)
	require.EqualError(t, err, `"fn" is already exported in module "test"`)

	// Any side effects should be reverted
	require.Equal(t, []*FunctionInstance{fn}, s.Functions)
	require.Equal(t, map[string]*ExportInstance{"fn": exp}, hostModule.Exports)
}

func TestStore_ExportImportedHostFunction(t *testing.T) {
	s := NewStore(context.Background(), &catchContext{})

	hf, err := NewGoFunc("host_fn", func(wasm.ModuleContext) {})
	require.NoError(t, err)

	// Add the host module
	hostModule := &ModuleInstance{Name: "", Exports: make(map[string]*ExportInstance, 1)}
	s.ModuleInstances[hostModule.Name] = hostModule
	_, err = s.AddHostFunction(hostModule, hf)
	require.NoError(t, err)

	t.Run("ModuleInstance is the importing module", func(t *testing.T) {
		_, err = s.Instantiate(&Module{
			TypeSection:   []*FunctionType{{}},
			ImportSection: []*Import{{Type: ExternTypeFunc, Name: "host_fn", DescFunc: 0}},
			MemorySection: []*MemoryType{{1, nil}},
			ExportSection: map[string]*Export{"host.fn": {Type: ExternTypeFunc, Name: "host.fn", Index: 0}},
		}, "test")
		require.NoError(t, err)

		ei, err := s.getExport("test", "host.fn", ExternTypeFunc)
		require.NoError(t, err)
		os.Environ()
		// We expect the host function to be called in context of the importing module.
		// Otherwise, it would be the pseudo-module of the host, which only includes types and function definitions.
		// Notably, this ensures the host function call context has the correct memory (from the importing module).
		require.Equal(t, s.ModuleInstances["test"], ei.Function.ModuleInstance)
	})
}

func TestFunctionInstance_Call(t *testing.T) {
	type key string
	storeCtx := context.WithValue(context.Background(), key("wa"), "zero")

	notStoreCtx := context.WithValue(context.Background(), key("wazer"), "o")

	tests := []struct {
		name     string
		ctx      context.Context
		expected context.Context
	}{
		{
			name:     "nil defaults to store context",
			ctx:      nil,
			expected: storeCtx,
		},
		{
			name:     "set overrides store context",
			ctx:      notStoreCtx,
			expected: notStoreCtx,
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			engine := &catchContext{}
			store := NewStore(storeCtx, engine)

			// Define a fake host function
			functionName := "fn"
			hostFn := func(ctx wasm.ModuleContext) {
			}
			fn, err := NewGoFunc(functionName, hostFn)
			require.NoError(t, err)

			// Add the host module
			hostModule := &ModuleInstance{Name: "host", Exports: map[string]*ExportInstance{}}
			store.ModuleInstances[hostModule.Name] = hostModule
			_, err = store.AddHostFunction(hostModule, fn)
			require.NoError(t, err)

			// Make a module to import the function
			instantiated, err := store.Instantiate(&Module{
				TypeSection: []*FunctionType{{}},
				ImportSection: []*Import{{
					Type:     ExternTypeFunc,
					Module:   hostModule.Name,
					Name:     functionName,
					DescFunc: 0,
				}},
				MemorySection: []*MemoryType{{1, nil}},
				ExportSection: map[string]*Export{functionName: {Type: ExternTypeFunc, Name: functionName, Index: 0}},
			}, "test")
			require.NoError(t, err)

			// This fails if the function wasn't invoked, or had an unexpected context.
			_, err = instantiated.Function(functionName).Call(tc.ctx)
			require.NoError(t, err)
			if tc.expected == nil {
				require.Nil(t, engine.ctx)
			} else {
				require.Equal(t, tc.expected, engine.ctx.Context())
			}
		})
	}
}

type catchContext struct {
	ctx *ModuleContext
}

func (e *catchContext) Call(ctx *ModuleContext, _ *FunctionInstance, _ ...uint64) (results []uint64, err error) {
	e.ctx = ctx
	return
}

func (e *catchContext) Compile(_ *FunctionInstance) error {
	return nil
}

func (e *catchContext) Release(_ *FunctionInstance) error {
	return nil
}

func TestStore_checkFuncAddrOverflow(t *testing.T) {
	t.Run("too many functions", func(t *testing.T) {
		s := NewStore(context.Background(), &catchContext{})
		const max = 10
		s.maximumFunctionAddress = max
		err := s.checkFuncAddrOverflow(max + 1)
		require.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		s := NewStore(context.Background(), &catchContext{})
		const max = 10
		s.maximumFunctionAddress = max
		err := s.checkFuncAddrOverflow(max)
		require.NoError(t, err)
	})
}

func TestStore_getTypeInstance(t *testing.T) {
	t.Run("too many functions", func(t *testing.T) {
		s := NewStore(context.Background(), &catchContext{})
		const max = 10
		s.maximumFunctionTypes = max
		s.TypeIDs = make(map[string]FunctionTypeID)
		for i := 0; i < max; i++ {
			s.TypeIDs[strconv.Itoa(i)] = 0
		}
		_, err := s.getTypeInstance(&FunctionType{})
		require.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		for _, tc := range []*FunctionType{
			{Params: []ValueType{}},
			{Params: []ValueType{ValueTypeF32}},
			{Results: []ValueType{ValueTypeF64}},
			{Params: []ValueType{ValueTypeI32}, Results: []ValueType{ValueTypeI64}},
		} {
			tc := tc
			t.Run(tc.String(), func(t *testing.T) {
				s := NewStore(context.Background(), &catchContext{})
				actual, err := s.getTypeInstance(tc)
				require.NoError(t, err)

				expectedTypeID, ok := s.TypeIDs[tc.String()]
				require.True(t, ok)
				require.Equal(t, expectedTypeID, actual.TypeID)
				require.Equal(t, tc, actual.Type)
			})
		}
	})
}

func TestExecuteConstExpression(t *testing.T) {
	t.Run("non global expr", func(t *testing.T) {
		for _, vt := range []ValueType{ValueTypeI32, ValueTypeI64, ValueTypeF32, ValueTypeF64} {
			t.Run(ValueTypeName(vt), func(t *testing.T) {
				// Allocate bytes with enough size for all types.
				expr := &ConstantExpression{Data: make([]byte, 8)}
				switch vt {
				case ValueTypeI32:
					expr.Data[0] = 1
					expr.Opcode = OpcodeI32Const
				case ValueTypeI64:
					expr.Data[0] = 2
					expr.Opcode = OpcodeI64Const
				case ValueTypeF32:
					binary.LittleEndian.PutUint32(expr.Data, math.Float32bits(math.MaxFloat32))
					expr.Opcode = OpcodeF32Const
				case ValueTypeF64:
					binary.LittleEndian.PutUint64(expr.Data, math.Float64bits(math.MaxFloat64))
					expr.Opcode = OpcodeF64Const
				}

				raw := executeConstExpression(nil, expr)
				require.NotNil(t, raw)

				switch vt {
				case ValueTypeI32:
					actual, ok := raw.(int32)
					require.True(t, ok)
					require.Equal(t, int32(1), actual)
				case ValueTypeI64:
					actual, ok := raw.(int64)
					require.True(t, ok)
					require.Equal(t, int64(2), actual)
				case ValueTypeF32:
					actual, ok := raw.(float32)
					require.True(t, ok)
					require.Equal(t, float32(math.MaxFloat32), actual)
				case ValueTypeF64:
					actual, ok := raw.(float64)
					require.True(t, ok)
					require.Equal(t, float64(math.MaxFloat64), actual)
				}
			})
		}
	})
	t.Run("global expr", func(t *testing.T) {
		for _, tc := range []struct {
			valueType ValueType
			val       uint64
		}{
			{valueType: ValueTypeI32, val: 10},
			{valueType: ValueTypeI64, val: 20},
			{valueType: ValueTypeF32, val: uint64(math.Float32bits(634634432.12311))},
			{valueType: ValueTypeF64, val: math.Float64bits(1.12312311)},
		} {
			t.Run(ValueTypeName(tc.valueType), func(t *testing.T) {
				// The index specified in Data equals zero.
				expr := &ConstantExpression{Data: []byte{0}, Opcode: OpcodeGlobalGet}
				globals := []*GlobalInstance{{Val: tc.val, Type: &GlobalType{ValType: tc.valueType}}}

				val := executeConstExpression(globals, expr)
				require.NotNil(t, val)

				switch tc.valueType {
				case ValueTypeI32:
					actual, ok := val.(int32)
					require.True(t, ok)
					require.Equal(t, int32(tc.val), actual)
				case ValueTypeI64:
					actual, ok := val.(int64)
					require.True(t, ok)
					require.Equal(t, int64(tc.val), actual)
				case ValueTypeF32:
					actual, ok := val.(float32)
					require.True(t, ok)
					require.Equal(t, wasm.DecodeF32(tc.val), actual)
				case ValueTypeF64:
					actual, ok := val.(float64)
					require.True(t, ok)
					require.Equal(t, wasm.DecodeF64(tc.val), actual)
				}
			})
		}
	})
}

func TestModuleInstance_addExport(t *testing.T) {
	// TODO: backfill
}

func TestModuleInstance_GetExport(t *testing.T) {
	// TODO: backfill
}

func TestStore_addModuleInstance(t *testing.T) {
	// TODO:
}

func TestStore_ReleaseModuleInstance(t *testing.T) {
	// TODO:
}

func TestStore_releaseFunctionInstances(t *testing.T) {
	// TODO:
}

func TestStore_addFunctionInstancess(t *testing.T) {
	// TODO:
}

func TestStore_releaseGlobalInstances(t *testing.T) {
	// TODO:
}

func TestStore_addGlobalInstances(t *testing.T) {
	// TODO:
}

func TestStore_releaseTableInstances(t *testing.T) {
	// TODO:
}

func TestStore_addTableInstances(t *testing.T) {
	// TODO:
}

func TestStore_releaseMemoryInstance(t *testing.T) {
	// TODO:
}

func TestStore_addMemoryInstance(t *testing.T) {
	// TODO:
}

func TestStore_resolveImports(t *testing.T) {
	const moduleName = "test"
	const name = "target"

	t.Run("module not instantiated", func(t *testing.T) {
		s := NewStore(context.Background(), &catchContext{})
		_, _, _, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: "unknown", Name: "unknown"}}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "module \"unknown\" not instantiated")
	})
	t.Run("export instance not found", func(t *testing.T) {
		s := NewStore(context.Background(), &catchContext{})
		s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{}, Name: moduleName}
		_, _, _, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: moduleName, Name: "unknown"}}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "\"unknown\" is not exported in module \"test\"")
	})
	t.Run("func", func(t *testing.T) {
		t.Run("unknwon type", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {}}, Name: moduleName}
			_, _, _, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeFunc, DescFunc: 100}}})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unknown type for function import")
		})
		t.Run("signature mismatch", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {
				Function: &FunctionInstance{FunctionType: &TypeInstance{Type: &FunctionType{}}},
			}}, Name: moduleName}
			m := &Module{
				TypeSection:   []*FunctionType{{Results: []ValueType{ValueTypeF32}}},
				ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeFunc, DescFunc: 0}},
			}
			_, _, _, _, _, err := s.resolveImports(m)
			require.Error(t, err)
			require.Contains(t, err.Error(), "signature mimatch: null_f32 != null_null")
		})
		t.Run("ok", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			f := &FunctionInstance{FunctionType: &TypeInstance{Type: &FunctionType{Results: []ValueType{ValueTypeF32}}}}
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {
				Function: f,
			}}, Name: moduleName}
			m := &Module{
				TypeSection:   []*FunctionType{{Results: []ValueType{ValueTypeF32}}},
				ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeFunc, DescFunc: 0}},
			}
			functions, _, _, _, moduleImports, err := s.resolveImports(m)
			require.NoError(t, err)
			require.Contains(t, moduleImports, s.ModuleInstances[moduleName])
			require.Contains(t, functions, f)
		})
	})
	t.Run("global", func(t *testing.T) {
	})
	t.Run("table", func(t *testing.T) {
		t.Run("element type", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {
				Type:  ExternTypeTable,
				Table: &TableInstance{ElemType: 0x00}, // Unknown!
			}}, Name: moduleName}
			_, _, _, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeTable, DescTable: &TableType{ElemType: 0x1}}}})
			require.Error(t, err)
			require.Contains(t, err.Error(), "incompatible table improt: element type mismatch")
		})
		t.Run("minimum size mismatch", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			importTableType := &TableType{Limit: &LimitsType{Min: 2}}
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {
				Type:  ExternTypeTable,
				Table: &TableInstance{Min: importTableType.Limit.Min - 1},
			}}, Name: moduleName}
			_, _, _, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeTable, DescTable: importTableType}}})
			require.Error(t, err)
			require.Contains(t, err.Error(), "incompatible table import: minimum size mismatch")
		})
		t.Run("maximum size mismatch", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			max := uint32(10)
			importTableType := &TableType{Limit: &LimitsType{Max: &max}}
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {
				Type:  ExternTypeTable,
				Table: &TableInstance{Min: importTableType.Limit.Min - 1},
			}}, Name: moduleName}
			_, _, _, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeTable, DescTable: importTableType}}})
			require.Error(t, err)
			require.Contains(t, err.Error(), "incompatible table imports: maximum size mismatch")
		})
		t.Run("ok", func(t *testing.T) {
			s := NewStore(context.Background(), &catchContext{})
			max := uint32(10)
			tableInst := &TableInstance{Max: &max}
			s.ModuleInstances[moduleName] = &ModuleInstance{Exports: map[string]*ExportInstance{name: {
				Type:  ExternTypeTable,
				Table: tableInst,
			}}, Name: moduleName}
			_, _, tables, _, _, err := s.resolveImports(&Module{ImportSection: []*Import{{Module: moduleName, Name: name, Type: ExternTypeTable, DescTable: &TableType{Limit: &LimitsType{Max: &max}}}}})
			require.NoError(t, err)
			require.Contains(t, tables, tableInst)
		})
	})
	t.Run("memory", func(t *testing.T) {
	})

}

func TestModuleInstance_validateData(t *testing.T) {
	// TODO:
}

func TestModuleInstance_validateElements(t *testing.T) {
	// TODO:
}

func TestModuleInstance_buildExportInstances(t *testing.T) {
	// TODO:
}
