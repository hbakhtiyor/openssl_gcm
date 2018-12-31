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

type gcmEncryptReader struct {
	src io.Reader
	ctx openssl.AuthenticatedEncryptionCipherCtx
	eof bool
	buf *bytes.Buffer
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
	r.buf.Write(data)

	return r.buf.Read(p)
}

type gcmDecryptReader struct {
	src io.Reader
	ctx openssl.AuthenticatedDecryptionCipherCtx
	eof bool
	buf *bytes.Buffer
	tag *bytes.Buffer // openssl.GCM_TAG_MAXLEN
}

func NewGcmDecryptReader(r io.Reader, key, iv, aad []byte) (*gcmDecryptReader, error) {
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
		tag: &bytes.Buffer{},
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

	data, err := r.ctx.DecryptUpdate(p[:n])
	if err != nil {
		return len(data), fmt.Errorf("Failed to perform a decryption: %v", err)
	}
	r.buf.Write(data)

	return r.buf.Read(p)
}

// type DecryptWriter struct {
// 	writer io.Writer
// 	buffer []byte
// }

// func NewDecryptWriter(w io.Writer) (*DecryptWriter, error) {
// 	return &DecryptWriter{
// 		writer: w,
// 		buffer: make([]byte, 4096, 4096),
// 	}, nil
// }

// func (w *DecryptWriter) Write(p []byte) (int, error) {
// 	n := copy(w.buffer, p)
// 	// w.buffer[:n]
// 	return w.writer.Write(w.buffer[:n])
// }
