package openssl_gcm

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spacemonkeygo/openssl"
)

const (
	GcmTagMaxlen = openssl.GCM_TAG_MAXLEN
)

type gcmDecryptReader struct {
	src  io.Reader
	ctx  openssl.AuthenticatedDecryptionCipherCtx
	eof  bool
	buf  *bytes.Buffer // for finalize small bytes
	tag  *bytes.Buffer
	off  int64
	size int64
	// TODO possible to know the remaining bytes before eof instead of specifying size?
}

func NewGcmDecryptReader(r io.Reader, key, iv, aad []byte, size int64) (*gcmDecryptReader, error) {
	ctx, err := openssl.NewGCMDecryptionCipherCtx(len(key)*8, nil, key, iv)
	if err != nil {
		return nil, fmt.Errorf("Failed making GCM decryption ctx: %v", err)
	}

	if len(aad) > 0 {
		err = ctx.ExtraData(aad)
		if err != nil {
			return nil, fmt.Errorf("Failed to add authenticated data: %v", err)
		}

	}

	return &gcmDecryptReader{
		src:  r,
		ctx:  ctx,
		buf:  &bytes.Buffer{},
		tag:  &bytes.Buffer{},
		size: size - GcmTagMaxlen,
	}, nil
}

func (r *gcmDecryptReader) Read(p []byte) (int, error) {
	if r.eof {
		return r.buf.Read(p)
	}

	n, err := r.src.Read(p)

	if err == io.EOF {
		if err := r.ctx.SetTag(r.tag.Bytes()); err != nil {
			return n, fmt.Errorf("Failed to set an expected GCM tag: %v", err)
		}

		data, err := r.ctx.DecryptFinal()
		if err != nil {
			return len(data), fmt.Errorf("Failed to finalize decryption: %v", err)
		}
		r.buf.Write(data)

		r.eof = true

		return r.buf.Read(p)
	} else if err != nil {
		return n, err
	}

	r.off += int64(n)
	if r.off > r.size {
		d := int(r.off % r.size)

		d %= cap(p)
		if d == 0 {
			d = n
		}

		r.tag.Write(p[n-d : n])
		n -= d
	}

	if n > 0 {
		data, err := r.ctx.DecryptUpdate(p[:n])
		if err != nil {
			return len(data), fmt.Errorf("Failed to perform a decryption: %v", err)
		}
		copy(p, data)
	} // TODO if n == 0, read the remaining bytes and finalize
	return n, nil
}
