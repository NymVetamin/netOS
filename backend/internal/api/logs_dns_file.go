package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/netos-router/netos/internal/subsys/services"
)

const dnsPageBytes = 512 << 10

var errDNSFileChanged = errors.New("DNS-журнал изменился при ротации; обновите журнал")

type dnsFileStamp struct {
	ID       string `json:"id"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
}
type dnsFileOffset struct {
	File   int   `json:"file"`
	Offset int64 `json:"offset"`
}
type dnsFilePosition struct {
	Files [4]dnsFileStamp `json:"files"`
	Next  dnsFileOffset   `json:"next"`
}
type dnsFileLine struct {
	Text string
	ID   string
	Next dnsFileOffset
}

func (p dnsFilePosition) valid() bool {
	if p.Next.File < 0 || p.Next.File > 4 || p.Next.Offset < 0 {
		return false
	}
	for _, f := range p.Files {
		if len(f.ID) > 64 || f.Size < 0 {
			return false
		}
	}
	if p.Next.File == 4 {
		return p.Next.Offset == 0
	}
	return p.Next.Offset <= p.Files[p.Next.File].Size
}

// The base path is chosen by the server, never read from a cursor. Rotation
// invalidates the entire four-file snapshot; ordinary appends stay outside it.
// The returned position is a copy. Callers publish only consumed row offsets.
func readDNSFileBatch(ctx context.Context, base string, previous *dnsFilePosition) (rows []dnsFileLine, pos dnsFilePosition, err error) {
	if previous != nil {
		pos = *previous
		if !pos.valid() {
			return nil, pos, fmt.Errorf("неверный курсор DNS-файла")
		}
	}
	err = services.ReadDNSLogSnapshot(func() error {
		var files [4]*os.File
		defer func() {
			for _, f := range files {
				if f != nil {
					f.Close()
				}
			}
		}()
		for i := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			path := base
			if i > 0 {
				path += "." + strconv.Itoa(i)
			}
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				if previous != nil && pos.Files[i].ID != "" {
					return errDNSFileChanged
				}
				continue
			}
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("источник DNS не является обычным файлом")
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			files[i] = f
			opened, err := f.Stat()
			if err != nil {
				return err
			}
			if !os.SameFile(info, opened) {
				return errDNSFileChanged
			}
			id, err := dnsFileID(f, opened)
			if err != nil {
				return err
			}
			stamp := dnsFileStamp{ID: id, Size: opened.Size(), Modified: opened.ModTime().UnixNano()}
			if previous == nil {
				pos.Files[i] = stamp
			} else {
				old := pos.Files[i]
				if stamp.ID != old.ID || stamp.Size < old.Size || (i > 0 && (stamp.Size != old.Size || stamp.Modified != old.Modified)) {
					return errDNSFileChanged
				}
			}
		}
		if previous == nil {
			pos.Next = dnsFileOffset{Offset: pos.Files[0].Size}
		}
		cursor := pos.Next
		budget := int64(dnsPageBytes)
		for cursor.File < 4 && len(rows) < logScanSize+1 && budget > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			if cursor.Offset == 0 {
				cursor.File++
				if cursor.File < 4 {
					cursor.Offset = pos.Files[cursor.File].Size
				}
				continue
			}
			f := files[cursor.File]
			if f == nil {
				return errDNSFileChanged
			}
			start := max(int64(0), cursor.Offset-budget)
			data := make([]byte, cursor.Offset-start)
			n, err := f.ReadAt(data, start)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return errDNSFileChanged
				}
				return err
			}
			budget -= int64(n)
			end := len(data)
			if cursor.Offset == pos.Files[cursor.File].Size && data[end-1] != '\n' {
				end = bytes.LastIndexByte(data, '\n') + 1
				if end == 0 && start > 0 {
					return fmt.Errorf("строка DNS превышает лимит чтения страницы")
				}
				cursor.Offset = start + int64(end)
			}
			for end > 0 && len(rows) < logScanSize+1 {
				last := end
				if data[last-1] == '\n' {
					last--
				}
				first := bytes.LastIndexByte(data[:last], '\n') + 1
				if first == 0 && start > 0 {
					break
				}
				cursor.Offset = start + int64(first)
				rows = append(rows, dnsFileLine{Text: string(bytes.TrimSuffix(data[first:last], []byte{'\r'})), ID: pos.Files[cursor.File].ID + ":" + strconv.FormatInt(cursor.Offset, 10), Next: cursor})
				end = first
			}
			if len(rows) == 0 && cursor.Offset > 0 {
				return fmt.Errorf("строка DNS превышает лимит чтения страницы")
			}
		}
		// With no raw rows, only empty/incomplete files were crossed. Otherwise
		// each row carries its own next position for the bounded event merge.
		if len(rows) == 0 {
			pos.Next = cursor
		}
		return nil
	})
	if err != nil {
		return nil, pos, err
	}
	return rows, pos, nil
}
