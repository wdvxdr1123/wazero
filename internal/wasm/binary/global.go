package binary

import (
	"fmt"
	"io"

	wasm "github.com/tetratelabs/wazero/internal/wasm"
)

func decodeGlobal(r io.Reader) (*wasm.Global, error) {
	gt, err := decodeGlobalType(r)
	if err != nil {
		return nil, fmt.Errorf("read global type: %v", err)
	}

	init, err := decodeConstantExpression(r)
	if err != nil {
		return nil, fmt.Errorf("get init expression: %v", err)
	}

	return &wasm.Global{
		Type: gt,
		Init: init,
	}, nil
}
