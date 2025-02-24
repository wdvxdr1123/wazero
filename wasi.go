package wazero

import (
	"fmt"
	"io"

	internalwasi "github.com/tetratelabs/wazero/internal/wasi"
	internalwasm "github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/wasi"
	"github.com/tetratelabs/wazero/wasm"
)

// WASIDirFS returns a file system (a wasi.FS) for the tree of files rooted at
// the directory dir. It's similar to os.DirFS, except that it implements
// wasi.FS instead of the fs.FS interface.
func WASIDirFS(dir string) wasi.FS {
	return internalwasi.DirFS(dir)
}

func WASIMemFS() wasi.FS {
	return &internalwasi.MemFS{
		Files: map[string][]byte{},
	}
}

type WASIConfig struct {
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Args     []string
	Environ  map[string]string
	Preopens map[string]wasi.FS
}

// WASISnapshotPreview1 are functions importable as the module name wasi.ModuleSnapshotPreview1
func WASISnapshotPreview1() *HostModuleConfig {
	return WASISnapshotPreview1WithConfig(&WASIConfig{})
}

// WASISnapshotPreview1WithConfig are functions importable as the module name wasi.ModuleSnapshotPreview1
func WASISnapshotPreview1WithConfig(c *WASIConfig) *HostModuleConfig {
	// TODO: delete the internalwasi.Option types as they are not accessible as they are internal!
	var opts []internalwasi.Option
	if c.Stdin != nil {
		opts = append(opts, internalwasi.Stdin(c.Stdin))
	}
	if c.Stdout != nil {
		opts = append(opts, internalwasi.Stdout(c.Stdout))
	}
	if c.Stderr != nil {
		opts = append(opts, internalwasi.Stderr(c.Stderr))
	}
	if len(c.Args) > 0 {
		opt, err := internalwasi.Args(c.Args...)
		if err != nil {
			panic(err) // better to panic vs have bother users about unlikely size > uint32
		}
		opts = append(opts, opt)
	}
	if len(c.Environ) > 0 {
		environ := make([]string, 0, len(c.Environ))
		for k, v := range c.Environ {
			environ = append(environ, fmt.Sprintf("%s=%s", k, v))
		}
		opt, err := internalwasi.Environ(environ...)
		if err != nil { // this can't be due to lack of '=' as we did that above.
			panic(err) // better to panic vs have bother users about unlikely size > uint32
		}
		opts = append(opts, opt)
	}
	if len(c.Preopens) > 0 {
		for k, v := range c.Preopens {
			opts = append(opts, internalwasi.Preopen(k, v))
		}
	}
	return &HostModuleConfig{Name: wasi.ModuleSnapshotPreview1, Functions: internalwasi.SnapshotPreview1Functions(opts...)}
}

// StartWASICommand instantiates the module and starts its WASI Command function ("_start"). The return value are all
// exported functions in the module. This errs if the module doesn't comply with prerequisites, or any instantiation
// or function call error.
//
// Prerequisites of the "Current Unstable ABI" from wasi.ModuleSnapshotPreview1:
// * "_start" is an exported nullary function and does not export "_initialize"
// * "memory" is an exported memory.
//
// Note: "_start" is invoked in the StoreConfig.Context.
// Note: Exporting "__indirect_function_table" is mentioned as required, but not enforced here.
// Note: The wasm.Functions return value does not restrict exports after "_start" as allowed in the specification.
// Note: All TinyGo Wasm are WASI commands. They initialize memory on "_start" and import "fd_write" to implement panic.
// See https://github.com/WebAssembly/WASI/blob/snapshot-01/design/application-abi.md#current-unstable-abi
func StartWASICommand(store wasm.Store, module *ModuleConfig) (wasm.ModuleExports, error) {
	internal, ok := store.(*internalwasm.Store)
	if !ok {
		return nil, fmt.Errorf("unsupported Store implementation: %s", store)
	}
	m, err := decodeModule(module)
	if err != nil {
		return nil, err
	}

	moduleName := getModuleName(module.Name, m)

	if err = internalwasi.ValidateWASICommand(m, moduleName); err != nil {
		return nil, err
	}

	instantiated, err := internal.Instantiate(m, moduleName)
	if err != nil {
		return nil, err
	}
	ctx := instantiated.Context

	start := ctx.Function(internalwasi.FunctionStart)
	if _, err = start.Call(ctx.Context()); err != nil {
		return nil, fmt.Errorf("module[%s] function[%s] failed: %w", moduleName, internalwasi.FunctionStart, err)
	}
	return instantiated, nil
}
