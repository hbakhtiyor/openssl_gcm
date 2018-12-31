// package cipher
package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spacemonkeygo/openssl"
)

// Credits
// https://github.com/aws/aws-sdk-go/blob/master/service/s3/s3crypto/aes_gcm.go
// https://github.com/catalyzeio/gcm/blob/master/gcm/gcm.go
// https://github.com/spacemonkeygo/openssl/blob/master/ciphers_test.go
// https://github.com/marcopaganini/iocrypt/blob/master/iocrypt.go
// https://github.com/minio/sio/tree/master/cmd/ncrypt

const (
	GcmTagMaxlen = openssl.GCM_TAG_MAXLEN
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

type gcmDecryptReader struct {
	src  io.Reader
	ctx  openssl.AuthenticatedDecryptionCipherCtx
	eof  bool
	buf  *bytes.Buffer // for finalize small bytes
	tag  *bytes.Buffer
	off  int64
	size int64
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
		src: r,
		ctx: ctx,
		buf: &bytes.Buffer{},
		// tag:  make([]byte, 0, GcmTagMaxlen),
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

		// m := n - GcmTagMaxlen
		// if m < 0 {
		// 	m = 0
		// }
		// r.tag = append(r.tag, p[m:n]...)
		// if len(r.tag) > GcmTagMaxlen {
		// 	r.tag = r.tag[len(r.tag)-GcmTagMaxlen:]
		// }
	}

	data, err := r.ctx.DecryptUpdate(p[:n])
	if err != nil {
		return len(data), fmt.Errorf("Failed to perform a decryption: %v", err)
	}
	copy(p, data)

	return n, nil
}
