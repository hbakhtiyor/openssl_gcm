package openssl_gcm

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spacemonkeygo/openssl"
)

type gcmEncryptReader struct {
	src io.Reader
	ctx openssl.AuthenticatedEncryptionCipherCtx
	eof bool
	buf *bytes.Buffer // for finalize small bytes
}

func NewGcmEncryptReader(r io.Reader, key, iv, aad []byte) (*gcmEncryptReader, error) {
	ctx, err := openssl.NewGCMEncryptionCipherCtx(len(key)*8, nil, key, iv)
	if err != nil {
		return nil, fmt.Errorf("Failed making GCM encryption ctx: %v", err)
	}

	if len(aad) > 0 {
		err = ctx.ExtraData(aad)
		if err != nil {
			return nil, fmt.Errorf("Failed to add authenticated data: %v", err)
		}
	}

	return &gcmEncryptReader{
		src: r,
		ctx: ctx,
		buf: &bytes.Buffer{},
	}, nil
}

func (r *gcmEncryptReader) Read(p []byte) (int, error) {
	if r.eof {
		return r.buf.Read(p)
	}

	n, err := r.src.Read(p)

	if err == io.EOF {
		data, err := r.ctx.EncryptFinal()
		if err != nil {
			return len(data), fmt.Errorf("Failed to finalize encryption: %v", err)
		}
		r.buf.Write(data)

		tag, err := r.ctx.GetTag()
		if err != nil {
			return len(data) + len(tag), fmt.Errorf("Failed to get GCM tag: %v", err)
		}
		r.buf.Write(tag)

		r.eof = true

		return r.buf.Read(p)
	} else if err != nil {
		return n, err
	}

	data, err := r.ctx.EncryptUpdate(p[:n])
	if err != nil {
		return len(data), fmt.Errorf("Failed to perform an encryption: %v", err)
	}
	copy(p, data)

	return n, nil
}
