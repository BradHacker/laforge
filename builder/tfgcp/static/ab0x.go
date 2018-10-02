// Code generated by fileb0x at "2018-10-01 20:12:47.273786623 -0700 PDT m=+0.027141484" from config file "assets.toml" DO NOT EDIT.
// modification hash(8acb4071ffc3bd99afcfcae5df25a04a.e5b9c5ef4c0b7aef8593382d0449dfd6)

package static

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path"

	"golang.org/x/net/webdav"
)

var (
	// CTX is a context for webdav vfs
	CTX = context.Background()

	// FS is a virtual memory file system
	FS = webdav.NewMemFS()

	// Handler is used to server files through a http handler
	Handler *webdav.Handler

	// HTTP is the http file system
	HTTP http.FileSystem = new(HTTPFS)
)

// HTTPFS implements http.FileSystem
type HTTPFS struct{}

// FileCommandTfTmpl is "command.tf.tmpl"
var FileCommandTfTmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xb4\x93\x31\x8f\xd4\x30\x10\x85\x7b\xff\x8a\x91\x45\x01\x12\x44\x14\x88\xee\x0a\xb8\x02\xe8\x10\x14\x14\xe8\x64\xe5\xe2\xd9\xdb\x11\xf1\x4c\xe4\x99\xec\xde\x29\xca\x7f\x47\x93\x90\xb0\xc5\x22\x41\x81\x9b\x64\xf4\x66\x9e\x9f\x3f\xd9\xd3\x04\x19\x0f\xc4\x08\xb1\x93\x52\x5a\xce\x11\xe6\x39\x54\x54\x19\x6b\x87\x10\x79\xec\xfb\xb4\x95\x11\xe2\x50\xe5\x44\x4a\xc2\x69\x9a\xa0\xf9\x80\x06\x71\x53\x13\xb7\x05\x7d\x3c\xa9\xe1\xb0\xcb\x5e\x24\x1e\xcb\x3d\x56\x17\x23\x4c\x01\x20\xe3\x80\x9c\x35\x09\xc3\x0d\x7c\x0f\x00\x00\x91\xee\x4b\xea\xa4\x0c\xa3\x61\x3a\x95\x44\xac\xd6\x72\x87\xcd\x9f\x37\x8a\x01\xe0\x2e\x04\x80\x3d\x15\x56\x6f\x2b\x62\xf8\x0a\x1f\xb1\x5b\x37\x03\x98\x26\xa0\x03\x34\x1f\x45\xad\xf9\xa4\xdf\x88\xb3\x9c\xd5\x0f\x0a\xcb\xea\x84\x19\x3b\x23\xe1\x5f\xfd\xbe\x8e\xa2\xb6\xfc\xdc\x40\x7c\x36\xfd\x7b\xb8\x86\x86\xd3\x9b\xd4\xe6\x5c\x51\x75\x89\xba\x2e\x7b\x1a\x70\xf3\x3d\x13\xd7\xf2\x5b\x1a\x15\xeb\x26\xbd\xcb\x85\x98\xd4\x6a\x6b\x52\x2f\xa6\xa9\xa0\x8c\xb6\xb4\xbc\x7d\x7d\x31\x3b\xb4\xaa\x67\xa9\xd9\x05\x0f\x75\x2b\x65\x40\x23\x3f\x54\xf3\x45\xc4\x3e\x6f\xfa\xbc\x67\x99\x37\x36\xd8\x2b\xfe\x2d\x8d\xff\x08\x64\xb5\x56\x3d\x5e\x21\xb2\x6a\x55\xc4\xae\xb0\x80\x2b\x38\x2a\x9d\x5a\xc3\xf4\x03\x9f\xd6\xbc\x07\xea\xf1\xb9\x93\x21\xce\xf8\x08\xcd\xfb\x91\xfa\xdc\xdc\x0a\x1f\xe8\xc1\xc3\xf6\x49\xf5\x98\x2e\xc6\x92\x4f\x2c\xb7\xec\xc5\x15\x62\xec\x20\xc3\x52\x12\xf7\xfe\x80\xb6\x7b\x0c\x3b\x7f\x7f\x4e\xdb\xf7\xab\x55\xe2\x07\x77\x7b\xb9\x74\xdd\x05\x77\x9b\xc3\xee\xf5\x33\x00\x00\xff\xff\x0d\x32\x43\xcf\x8a\x03\x00\x00")

// FileDNSRecordTfTmpl is "dns_record.tf.tmpl"
var FileDNSRecordTfTmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x64\x8f\x31\x4b\x04\x31\x14\x84\xfb\xf7\x2b\x86\xd4\xb2\x1c\x68\xbb\x9d\x60\x77\x85\x82\x85\x22\x21\x5e\x9e\xb0\x70\x97\x2c\xef\x65\xb7\x30\xbc\xff\x2e\xc9\xde\x5e\xe1\x75\xc9\xcc\x97\x99\x49\xad\x88\xfc\x33\x25\x86\x8b\x49\xbd\xf0\x29\x4b\x74\x30\xa3\x59\xf2\x3a\x45\x96\x6e\x38\x54\x02\x96\x39\x86\xc2\xfd\x08\x28\xcb\xca\x82\x11\xae\x56\x0c\x2f\x5c\xb6\x84\x4d\xf6\xc2\x9a\x17\x39\x71\x8b\x1a\xa6\x79\x7d\xf2\x21\x46\x61\x55\x47\x80\x91\x11\xed\xc4\xf6\x2c\x5c\xab\xbd\x72\x71\x70\xbd\x5c\xa7\x9c\xfc\x2d\x7c\xe7\x7d\x0a\x97\x1e\xeb\xb5\xf0\x7c\xb3\xdb\xc5\xa7\xe5\xf2\xcd\xd2\xcc\x6d\xf0\x6f\x4e\xbc\x2f\x7c\x3e\xbe\xbd\xf6\x8a\xe1\xa3\xa9\x66\x43\x9b\xd2\xc2\xee\x89\x63\x53\xcd\x1a\x70\x9d\xcd\x8a\x11\x9f\xfd\xe3\xff\xd8\xf7\x70\x5e\x3a\xfc\x40\xc0\x17\x01\xa5\x9c\x31\xe2\xf1\x70\x20\xa3\x5a\xc1\x29\xc2\xec\x2f\x00\x00\xff\xff\x4f\xd5\x7d\xe3\x68\x01\x00\x00")

// FileInfraTfTmpl is "infra.tf.tmpl"
var FileInfraTfTmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xe4\x5a\x5f\x4f\xe3\x3a\x16\x7f\xef\xa7\xb0\x32\xa0\xa5\x12\xc9\x40\xb9\xcb\x65\x90\x78\x60\x80\x99\x45\x77\x16\x56\xc0\xdd\xfb\x30\x42\x96\x1b\x9f\xb6\x5e\x12\x3b\xeb\xe3\x14\x18\xd4\xef\xbe\xb2\x9d\x34\x49\x9b\xb6\x50\x60\x56\xbb\xb7\x0f\x4c\x13\x9f\x73\x7c\xce\xef\xfc\xb5\x3b\x1f\xd6\xff\x74\x3e\x90\x6f\xc7\x5f\x2e\xaf\xbe\x9e\x91\xaf\x67\x17\x67\x57\xc7\x37\x67\xa7\xe4\xe6\xec\xea\xca\xbe\xfc\x3b\x39\xb9\xbc\xf8\x72\xfe\xf5\xf7\xab\xe3\x9b\xf3\xcb\x8b\xce\x07\x12\x86\xe4\x8f\xe3\xab\x8b\xf3\x8b\xaf\x24\x0c\x3b\x1f\xc8\xcd\x48\x20\x19\x88\x04\x88\x40\xc2\x72\xa3\x52\x66\x44\xcc\x92\xe4\x91\x0c\x41\x82\x66\x06\x78\x44\x4e\x15\x91\xca\x10\xe0\xc2\x10\x61\xfe\x82\x9d\x0f\x24\x56\xd2\x80\x34\x48\xb8\xd0\x10\x9b\xe4\x31\x22\xbf\x23\x90\x6f\x6c\xa0\xf4\x10\x08\x93\x9c\x68\x20\xfd\x5c\x24\x9c\x98\x72\x93\xa8\xf3\x1a\x4b\x3b\x06\xb4\xb6\xf2\x53\xf2\xd4\x21\xa4\xcf\xe2\x3b\x90\x9c\x04\x60\x62\x3e\xde\x0b\xdc\x4b\x42\x32\x0d\x03\xf1\x40\x8e\x48\x80\x86\x19\xf8\xf8\xf4\x44\x36\xa2\xcf\x56\x8f\xe8\xfc\x94\x4c\x26\xfe\xc5\x0d\xb0\xd4\xfd\xb9\xc8\xd3\x3e\x68\xfb\x7e\x2a\x3d\x32\x03\xc7\x1a\x38\x79\x20\x79\xa6\x84\xb5\xf4\x88\x7c\x77\x6f\x08\x09\x46\xc6\x64\x78\xf8\xd1\xca\x12\x92\xc3\xc3\x74\x8b\x13\x25\x07\x62\xe8\x75\xa2\x29\x43\x03\x3a\x20\x93\x49\xb0\xfd\x32\x4e\x4c\xd8\x18\x6a\x8c\xb7\xee\x6f\x8e\xa0\x25\x4b\xc1\x1a\xb7\x9c\xbf\xa4\x74\x22\x3c\x2c\x0c\xf1\x5e\x69\xbe\x9a\xb7\xa4\x2c\x79\x27\x9d\x49\xa7\x33\x66\x5a\xb0\x7e\x02\x24\x18\xa7\x28\x7e\x80\x47\xdb\x3c\x66\x4e\x99\x94\x65\x96\x92\xc3\x80\xe5\x89\x21\x47\x85\x2b\x02\x4c\x59\x92\x04\x96\x42\xee\x86\x68\x98\xe4\x4c\xf3\x70\xd7\x6b\x14\xa4\xc0\x45\x9e\xce\x2d\xf7\x8a\xe5\x84\xe9\x21\xcc\xad\xfe\x52\xac\x3e\xb4\x2f\xef\xf5\x5a\x55\x56\xf8\x3c\x85\xf3\x7e\x2e\x4d\xbe\xbb\xef\xe4\xfa\x87\x50\x61\x18\x27\x2a\xe7\x1f\x8b\xe7\xdd\xfd\x9d\x5f\xc2\xc4\x60\xd0\x60\x39\x58\xca\x72\xd0\x60\x89\x41\x1a\x85\xbf\x3a\x0e\xff\xbd\x20\x2f\x1e\x7e\x6d\xd0\xed\x2f\xa4\xdb\x2f\xe8\x38\xf4\x05\x93\x4b\x35\x48\x85\x14\x29\x4b\x66\x35\xf1\x9c\x9f\x1c\xa7\xff\x5e\xb0\x15\x0f\x9f\x0a\xba\xfb\xde\xdd\x9e\x23\xba\x17\x92\xab\xfb\x52\x78\xf9\xd4\xdb\xd9\xdd\x0f\x63\xa5\xa1\x22\x3f\x58\x4a\xbe\x73\x10\xea\x5e\x45\xbc\xdb\x5b\x2e\xbc\xd7\xa4\xde\x5f\xa1\xca\x34\x04\x32\xad\xc6\x82\x83\x26\xc1\x50\xa9\x61\x52\x44\x6d\xac\x81\x83\x34\x82\x25\x36\xa7\x83\x8d\x27\x5b\x9a\xb6\x16\x67\xc5\x30\xce\xa8\xe5\xa1\x96\xce\x65\x45\xd7\x25\x46\xa6\xd5\xbf\x20\x36\x4b\x33\xca\xf2\x16\x74\x65\x3e\x69\x18\x0a\x25\x57\x72\x79\x32\xcf\x34\xe9\x74\x34\xa0\xca\x75\x0c\xa5\x29\x34\x56\x69\x96\x1b\xa0\x12\xcc\xbd\xd2\x77\x01\x09\xc6\x59\xec\x0d\xac\xd5\x88\x8d\xe8\x4c\x8e\x85\x56\x32\x05\x69\x7c\x01\x0c\xcd\x82\x0a\x18\x5a\x01\x1d\xe2\xda\x80\x35\x98\x19\xa0\x98\xf7\x8b\x0d\x2c\x56\x03\x96\x20\x2c\xd5\x66\x20\x34\xdc\xbb\xa4\x0f\x58\x92\xa8\x7b\x2a\xe2\x34\x7b\x9d\x56\x4e\x4e\xe8\xe4\x58\x29\x5e\x1b\xef\xb8\x76\x28\xa2\x71\x16\x47\x08\xc9\x80\x26\x42\xde\x4d\x82\x8e\xb5\xc9\x0a\x99\x76\x08\x65\x54\xac\x12\x2b\xa3\x14\x3b\xb1\x44\xde\x26\xaa\x99\x1c\x42\x55\xee\x17\xbb\x69\x9c\xc5\x34\x16\xbc\xaa\xf0\xb7\x2f\xc3\x86\xf1\x54\xc8\xb7\x00\xc7\x0b\x7a\x67\x74\x16\x11\x99\x78\x35\x4d\xce\xd7\x47\xd9\x19\x47\x45\x66\x51\xfe\xb8\xd7\x5b\x07\xe8\x31\x17\x14\x1e\xcc\x5b\x40\x3d\xe6\x22\xb4\xa2\xde\x1e\xec\x02\x47\x42\x32\xa5\x9b\xd3\x46\xaf\x57\xcd\x0f\x7b\x7b\x07\x9f\x6a\x43\xc1\x1b\x22\x6a\xdb\xa3\xed\xa9\x86\x1a\x36\x6c\x8a\x79\x59\x15\xe1\x62\x5d\x1f\x09\xf9\x66\x3e\xb2\xa2\xfe\x4f\x13\xa2\xa5\xec\xbc\x8b\xef\x9e\x9e\x88\xd3\x89\x6c\x48\x30\xd6\x23\xdb\xee\x1b\x39\x3c\x9a\x15\x2a\xe3\x24\xe7\xc0\x2f\xca\x4e\x31\x99\x2c\x76\x7c\xd5\x51\x02\xaf\x5f\x21\xdc\x1a\xf3\x2a\xdf\x17\xb2\x3c\x99\x05\x57\x64\x0e\x26\x0f\x6c\x29\xd1\x52\x9c\x9c\x9f\x5e\xad\xdf\x8c\xd7\x0b\xaa\x17\xe5\xc2\x3b\xc0\x52\xc8\x2a\xbb\xa9\xec\xab\x5c\xf2\xff\xb1\x0c\x79\xab\xd8\x7e\xab\x6c\x99\x71\x53\x99\x38\x4f\x4f\xf6\xd0\x68\x93\xa0\x99\x42\xdb\x64\x63\xa4\xd0\xe0\x7c\x02\xfd\x4d\xa1\xf9\xfc\x58\xa4\x8f\x65\x24\xa4\xe2\xb4\x3c\x82\x3f\x14\xdc\x8e\xd9\x8b\x71\x74\x8e\x72\xa3\x0c\x2d\xea\x74\x39\x3c\x22\x99\x16\xd2\x0c\x48\xb0\x89\xa1\xd9\xe4\xe1\x26\x86\x9b\x18\xcc\x5b\x37\x6f\x96\xcb\x70\xb7\x81\xd3\xaa\xb0\xad\xe3\x76\x5a\x18\xc0\x8c\x73\x0d\x88\x45\x42\x37\x95\x29\xe3\xd7\x7e\xea\x31\x3c\x47\xe5\x68\x56\xed\x24\xa4\x3d\xea\xc5\xf0\x06\x5b\x11\x92\xb2\x78\x24\x24\xd0\xf2\x54\xb8\xf1\x34\x66\x3a\xf2\x07\xdc\xef\x8e\xd3\xe1\x70\x5e\xec\x79\x2d\x7e\x38\xee\xdb\xa9\x80\x1f\x4a\xc2\xca\xda\x61\x89\x7c\xe5\x28\xb8\xfa\x4a\x19\xca\x05\xde\x4d\x95\x25\x44\x48\x61\x0f\x24\xe2\x07\xd0\x8c\x69\x96\x62\x6d\x8d\x10\xab\x50\x69\x8c\x53\xe9\x54\xe0\x5d\x54\xea\x53\x23\x2c\x2d\xc9\x78\x88\xc8\xeb\x2b\x22\x65\xc3\x86\x91\x0a\x6b\x26\x5e\x5e\x37\x0d\xb3\x8e\x28\xff\x2d\x01\xf5\xd1\x69\x7b\x34\xe8\x01\x8b\xa1\xa6\x61\x55\xd3\x5b\xcb\x48\xb5\x1c\x15\x29\x43\x26\x93\x46\x41\x29\x05\x15\x81\xe4\xa5\xd8\xe2\x6d\xb5\x73\x47\xb3\xad\x12\xe0\xa5\x8d\xc7\xca\xee\x4e\xeb\xfb\x36\x99\x1a\xf8\x8d\xa1\xb9\x8c\x8d\xdb\xb9\x5b\xb9\x82\x10\x16\xc7\x80\x48\x63\xef\xb0\x3a\xe8\x92\x19\x2a\xb2\x56\x83\x0a\x35\xa3\xb6\xe0\x8a\x8a\xc5\x65\x58\x5a\xbe\x9c\xbb\x42\x50\xda\xe5\xb4\xbc\x8e\xb5\xc8\x0c\x36\x5f\xfe\x93\x69\x24\x41\x8e\xa0\x29\x67\x86\x51\x74\x44\x54\xf0\xa0\xdb\x9d\xa6\x26\x21\x29\x18\x66\xd7\x6b\x36\x8c\xca\x04\xae\x87\x4e\x2d\xab\xeb\xde\x70\x35\xee\x44\xa5\x19\x18\x61\x84\x92\xd1\xe9\xc5\x75\x74\xa5\x94\x39\x55\x29\x13\xb2\x11\x67\x36\xdc\x07\x65\x72\xe0\x1f\xfe\xe4\x5d\x96\x23\xfb\x29\x0f\xe3\x68\x98\x36\x79\x16\x7a\x95\xc3\x0c\x77\xdd\x7d\x0d\x18\x77\x95\x45\xdc\x1c\x2a\xd0\x68\x66\x94\x26\x1f\x59\x6c\xc4\x18\x0e\x1f\x01\xab\xad\xf0\x11\x33\x0d\x59\x88\x19\xc4\x3e\x3f\x66\x84\xd5\x4e\xef\x65\xf2\x5d\x41\x72\x8c\x08\xe6\x8b\xd2\xb6\xb0\xb5\x14\xb9\xad\xaa\x3c\x52\x57\x17\x9b\xc8\x58\xdf\x44\x9f\x19\x42\xb7\x3a\xec\x4f\x2d\x87\x04\xa1\x6e\x2b\xe2\xe8\x37\x78\x74\x21\xab\x95\x32\x87\x2b\xaf\x13\x34\x24\x14\x71\x44\xb3\xbc\x9f\x88\x98\xde\xc1\xe3\xec\xc5\x42\xb5\x97\x6f\x23\xd3\xe8\xe9\xd4\xf1\x97\x30\xe7\x02\xa3\xf3\x9a\x6e\x65\x44\xd0\xc2\x0d\x45\xe4\xfc\x6c\xd4\x6a\xed\xb0\x28\x52\xf5\xa6\xfb\x9a\xc6\x5b\xbf\x58\x25\xd3\xf1\xae\xe5\xed\x6c\xe0\xd7\xd7\x17\x6d\x32\x2b\x63\x5e\xbf\xd6\x5d\x5a\x57\xe6\x1a\x50\xb9\x7e\x5b\x62\xc2\x21\x03\xc9\x91\xba\x59\xf4\xfb\x4c\xa6\x55\x9e\x3e\xf5\x41\x16\x72\x89\x41\x3d\x08\x03\x99\x27\x09\x2d\xb7\x89\xb8\x44\xea\xee\xbe\x50\x28\x09\xbc\xa6\x4e\x25\xd0\x22\x15\xd8\x99\xa8\x2e\x67\xba\xbc\xd5\x1e\xbb\x78\x27\x32\xca\x78\xd0\x25\x81\x8d\xb5\xe5\xbc\x4e\xe5\x1b\xeb\xec\x80\xbb\x22\x12\xc6\x4a\x1a\xad\x92\x04\x74\xab\x84\x19\x2b\x18\x5f\x6c\x44\x23\x33\xd6\x7b\x73\x5b\x1f\x38\x54\x6e\xb2\xdc\x2c\x28\x93\x99\x16\x63\x66\x87\x8f\xac\x9a\x2f\xc6\x2c\xc9\xa1\xb5\x39\x94\x23\x4a\x7b\x77\x98\x6b\xa3\xd1\xce\x4c\xc7\x78\x96\x46\xbe\x76\xbc\x9b\x42\xf5\xa6\x68\x9f\x11\xc5\x50\x02\xa7\xbe\x27\x36\x15\xf5\x7e\x1f\x1a\xb2\x95\x80\x2c\x74\xfd\xc7\xd4\x6f\x1a\xbb\x64\xa7\x02\xbd\x1a\x6b\xd1\x40\x46\xa5\xcb\xb6\x6d\xb2\x61\x1d\x3d\x1d\x6d\x1b\xec\x33\x2e\xdc\xc0\xbc\xef\x7e\x7b\x7a\x28\x0e\xa2\x27\x89\x1d\xc2\xe6\xe2\x10\xfe\xdd\xd8\xa2\xae\x43\x29\x89\x3a\x01\x95\xbc\xe8\xda\xa6\x44\x95\x89\x41\x55\xf1\x16\x21\xea\xca\x60\x03\xd2\xee\x6c\xc8\xcd\xb4\x8b\x17\x6f\xdd\xcc\x89\x69\x42\xd0\x4d\xa4\xd6\xbe\x4d\x3e\xab\x01\xd9\x3a\x85\x58\x37\xac\xef\x76\x57\xa6\x46\x01\x99\x95\x1f\xfd\x26\x24\x27\x81\x2d\x22\x1a\xe2\xe2\x97\xa0\x67\x19\xd0\xd0\x23\x98\x0f\xb6\xe7\xa1\x20\x91\x22\xe8\x31\xe8\xa9\xd9\xc1\xa2\x7a\xa4\xdd\x28\x2d\xd1\x66\x42\xf7\xb9\x1b\xd4\x80\xa9\xe1\xec\x80\xac\x63\xf6\x0c\x71\xc7\xc6\xb0\x78\x54\x44\xaf\x3f\x9e\xcd\x32\x19\x48\xb3\x84\x19\x68\xe2\x59\x8f\xe2\x97\x7b\x46\x43\xaa\xdc\xb5\x41\x02\x3f\xd7\x35\xff\x25\xe4\x1a\xf6\xbe\x0e\xba\x58\xa5\x29\x93\xfc\x4f\x01\xdb\xd4\xd6\xd7\x41\xe6\xa7\xc6\x3f\x05\x62\xa5\xa9\xcf\x04\xac\xf9\x3c\x33\xe7\x56\x58\x2e\x1b\xdd\xac\xce\x09\x43\x43\x4b\xb3\xac\xfe\xae\x7e\x2f\xec\xa6\xd5\x20\x3d\x77\x4b\x82\x46\x69\x36\x04\xda\xcf\xe3\x3b\x30\x54\xf5\xfd\xef\x8e\xad\x33\x68\x58\x69\x53\x9d\x18\xdd\x1a\x69\xbd\x66\x74\x85\xb7\x1a\xbf\x9f\x3b\xae\xd7\x36\x8a\x8c\xff\xdd\xc4\x7f\x8a\xff\x40\xf2\x2e\x23\x94\xbb\x65\x71\x18\xac\xbc\x9d\x69\x42\xd6\xb8\xa7\x59\x38\x95\x93\xc5\x03\xc1\xd2\x69\xbf\x65\xc6\xad\xfa\x79\x1b\xa7\x8b\x8a\xf9\x10\x69\x88\xbc\x9d\xbd\x5c\xa8\xa2\xa2\xb1\x55\xe0\x3b\x50\x7d\xa2\xae\x39\xde\x68\x31\x1c\xda\x69\xab\x7e\x03\x52\x5a\x45\x05\x5f\xc3\x4d\x35\xee\xc9\xf6\x94\xb7\x35\x44\xa3\xa5\x01\x1a\xa5\xfc\xaf\x23\x86\xa3\xc6\x8d\xca\xbb\xfa\x68\x7d\x5d\x7f\x96\xaf\x5b\xcb\x8f\xaf\x37\x6b\x1e\xbf\xd6\xab\x44\xab\x42\x6e\xe6\x0c\x57\x0b\xaf\xc5\x7e\xfb\x79\xa8\x55\xdf\x6b\xc5\xfb\x3f\x01\x00\x00\xff\xff\x5d\x00\x82\x5d\x8d\x27\x00\x00")

// FileRemoteFileTfTmpl is "remote_file.tf.tmpl"
var FileRemoteFileTfTmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xc4\x53\x3d\x8f\xd4\x40\x0c\xed\xf3\x2b\xac\xd1\x15\xd0\x8c\xae\xa2\xbb\x02\x0e\xf1\xd1\xa1\xa3\xa0\x40\x68\x14\x32\xce\xae\x75\x89\x1d\x8d\x9d\x5b\x4e\xa3\xfc\x77\x34\x93\x4d\x58\x89\x45\x82\x0a\x57\x6b\x3d\xbf\xf5\x7b\x6f\xe2\x9c\x21\x62\x4f\x8c\xe0\x12\x8e\x62\x18\x7a\x1a\xd0\xc1\xb2\x34\x09\x55\xe6\xd4\x21\x38\x9e\x87\x21\x6c\xad\x03\x37\x25\x79\x22\x25\xe1\x90\x33\xf8\xf7\x68\x85\xbc\xa2\x81\xdb\xb1\xd2\x83\x1a\x4e\x3b\x5c\x9a\xc0\xf3\xf8\x1d\x53\x01\x1d\xe4\x06\x20\xe2\x84\x1c\x35\x08\xc3\x1d\x7c\x6d\x00\x00\xdc\x41\xe4\x30\x60\xe8\x64\x9c\x66\xc3\x40\xac\xd6\x72\x87\xfe\xcf\x8b\x5c\x03\xf0\xad\x69\x00\x76\x55\x98\xc0\xad\x2e\x72\xfd\xd3\x9c\x81\x7a\xf0\x1f\x44\xcd\x7f\xd4\x2f\xc4\x51\x4e\x5a\x1c\x42\xad\x4e\x98\xb1\x33\x12\x3e\xcf\x97\x3a\x8a\x5a\xfd\x71\x07\xee\x26\xff\xbb\x2a\xcf\x68\x27\x49\x8f\x81\xd8\x30\xf5\x6d\x87\xfe\xd6\xb7\x5d\x87\xaa\xa1\x13\xee\xe9\x50\x7a\x55\x3a\x30\xc6\xc0\xad\x05\x9a\xaa\x95\xb5\xec\x79\xc2\x6d\xfd\x89\x38\x8d\xbf\xa0\x59\x31\x6d\xd0\xeb\x38\x12\x93\x5a\x6a\x4d\xd2\x05\x9b\x46\x94\xd9\xea\xc8\xab\xdb\x0b\xee\xd4\xaa\x9e\x24\xc5\x02\x14\xed\xf7\x32\x4e\x68\x54\xbc\xfb\x07\x11\xfb\xb4\xe1\xcb\xae\x65\xd9\x22\xc4\x41\xf1\x6f\x43\xfb\xff\xb9\xad\x0a\x54\x8f\x57\x82\x5b\xb1\x24\x62\x57\x22\x83\x2b\xa9\x25\x7a\x6a\x0d\xc3\x23\x3e\xaf\xb6\xca\xc7\xf5\xa2\x04\x48\x1c\xf1\x07\xdc\xf8\x37\x33\x0d\xd1\xdf\x57\x7d\xc5\xd4\x10\x54\x8f\xe1\x82\xb7\x5f\x95\x7b\x79\x25\x59\x2e\x81\x37\xb5\x3d\x9f\xdc\xa6\xa3\x04\xf5\x50\xef\xf2\x1d\x0d\xe8\x3f\xaf\xe8\xf6\x3a\x11\xd5\x88\xdb\xfa\x0a\xbf\x0f\xbf\xbd\x40\x57\xc6\xd2\x2c\xcd\xbe\xef\x67\x00\x00\x00\xff\xff\x3e\x98\x0c\x0b\xfa\x03\x00\x00")

// FileScriptTfTmpl is "script.tf.tmpl"
var FileScriptTfTmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xec\x56\x4d\x6f\xe3\x36\x10\xbd\xeb\x57\x0c\x88\x2d\xb0\x8b\xc6\x4a\x17\x45\x7b\x58\x20\x87\x4d\xd0\x2f\xa0\x28\x82\xfa\xd0\x43\x1d\x10\xac\x38\x96\x89\x52\xa4\xc0\xa1\xd6\x0e\xb4\xfa\xef\xc5\x50\x96\x2c\xc7\x4e\x16\x0d\x92\xb4\xbb\x30\x0f\x41\xe8\xe1\x0c\x67\xde\x9b\x79\x62\xdb\x82\xc6\xa5\x71\x08\x82\x8a\x60\xea\x28\xa0\xeb\xb2\x80\xe4\x9b\x50\x20\x08\xd7\x58\x2b\x87\xad\x00\x51\x07\xff\xc1\x90\xf1\x4e\xb6\x2d\xe4\x3f\x61\x04\x31\x58\xa5\x53\x15\xb2\xbb\xa4\x88\xf5\x68\xe6\x8d\x74\x4d\xf5\x17\x86\x64\x6c\x6a\xeb\x95\x16\xd0\x66\x00\x31\x98\xb2\xc4\x40\x69\x03\x60\x1c\x45\xe5\x0a\x94\x46\xc3\x05\x88\x57\x6d\xe9\x7d\x69\x51\x16\xbe\xaa\x9b\x88\x72\xb0\xe7\xf7\xdf\x9d\x4f\x62\x74\x22\x03\xe8\xb2\x0c\x40\x63\x8d\x4e\x93\xf4\x0e\x2e\xe0\xcf\x74\x97\x18\x63\xec\x8c\x1c\x80\x7d\x6e\xd8\x67\xac\x14\x03\x88\xa5\xb1\x28\xb6\x59\xb6\x2d\x98\x25\xe4\x3f\x7b\x8a\xf9\x2f\xf4\x87\x71\xda\xaf\x89\x51\x03\xd8\x9a\x5f\x69\x8a\xec\x01\xef\x2e\xa0\x0e\xc6\xc5\x25\x88\xab\x77\xe7\x56\x2d\x7d\x28\x51\xf6\x40\xcb\xaf\x28\xaf\xe9\xad\x80\xd7\x87\x38\xbd\xd9\x85\x2b\xbc\x73\x58\x44\xe3\xdd\xf6\x7a\x5e\x2b\x4f\x31\xfd\x73\x0c\x25\xa5\x75\x40\xa2\x87\x40\xda\x1e\x49\xc5\xf6\x2b\xde\xd6\x38\x44\x5c\x1b\x17\xaa\x9d\xa9\x21\x0c\x83\xe9\xbd\xae\x8c\x33\x14\x83\x8a\x3e\x4c\xbc\x4d\x85\xbe\x89\xe9\xc8\xf7\xdf\x4c\x7c\x6b\x45\xb4\xf6\x21\xd1\xc9\xf9\x5c\xf9\xaa\xc6\x68\xb8\x9c\xfc\x77\xef\xe3\xf5\x60\xef\xc6\x5c\x12\x61\xbc\xb6\x2d\x38\x5c\xad\x88\x30\xd2\x39\x47\x49\xd0\xf3\x1f\x2e\x88\x7b\x8a\x7f\x9c\x27\x54\xf3\x4b\x45\x38\x89\xa6\x91\xa2\x71\x2a\xe1\xd7\xe7\x30\x92\x33\x1c\x6a\x5b\x40\x9b\x9c\x1e\x66\xf0\x3c\x78\x1f\x8f\x90\x48\xab\x47\x71\xa8\x4a\x74\x11\xc6\xf2\x96\xca\x12\x8a\x43\x86\x9f\x85\xe4\x3e\x28\xd1\xea\x08\xcb\xbd\x8d\x6b\x3d\xc2\x2f\x1c\xa1\x38\x98\x0f\x2a\xa2\xfc\x1b\x6f\xfb\x4c\x19\xb7\xd7\x8c\xb4\x71\x1a\x37\x90\x5f\x36\xc6\xea\xfc\xca\xbb\xa5\x29\x39\x4f\x2b\x89\x56\x72\xe2\x26\xfb\xe9\xea\x3a\xf1\x66\xd2\x05\x2f\xdf\x04\x4e\xf7\x94\x75\x59\x97\x3d\xab\x04\xe2\x06\x8b\xff\x5e\x00\xf7\xea\xca\x9f\x4c\xd8\xcf\x8e\x0a\x68\xc0\xca\x47\x9c\xed\x2a\x7f\xbc\x8e\x2e\x16\x8b\xc5\x49\x4a\xff\x95\x94\x1a\x67\xf9\x13\x3f\x50\x9f\xe8\xaf\xfd\x1a\x03\xad\xd0\x5a\x98\xfd\xe6\xaf\x83\x4f\x48\xcf\x7e\xd8\x60\xd1\x70\xd0\x6b\x6f\x4d\x71\x0b\x97\xb7\x7c\x31\xcc\x7e\x64\xeb\xe2\xce\xec\x2c\x44\xa2\x9b\xd7\xcd\x49\x4b\xff\xbf\x5a\xfa\x40\x1b\x14\xab\xca\x6b\xf8\x7a\x03\x77\x54\xf1\x6c\x77\x64\xdf\x32\x91\xd9\xf7\xa1\x9c\xc7\x60\x5c\x39\x75\xb8\x79\x79\x3d\x5d\x2b\x13\xbf\x3c\x3d\x4d\x5a\x39\xaa\x29\x93\x60\x8d\x6b\x36\x92\x2c\x62\x2d\xb9\x8d\x02\x8f\xd4\xb7\x3d\xc8\x6c\x5f\xf7\x1a\x7a\xf7\xc4\xdb\xef\xf8\x48\x36\x2a\xee\xaf\xbe\x50\xf6\x50\x72\xf7\xf4\xda\xf2\x99\x3d\xb9\xfe\xa4\x60\xf3\x6c\x56\x95\x72\x09\xea\x79\x54\x21\xce\xe6\x9c\xc8\xbd\xa9\xed\x84\xea\x40\x36\x1e\x8c\x75\x08\xc3\x7e\xa4\xa1\xef\xfa\x0e\x88\x18\xea\x80\x11\x03\x33\x25\xae\x59\xf5\xe6\xac\x7a\xe2\x0c\xc4\xec\xaa\xbf\x45\xf4\x4d\xbb\xc5\x71\x9a\xca\x93\x82\x42\x4f\x02\x07\x3d\x02\x88\xa1\xb2\xfe\x97\xe7\x1d\xc7\x97\x99\xc4\xb3\x97\x1c\xc5\x24\x30\xa7\x87\xcd\xe7\xf1\xb0\xd1\x68\xef\xfb\x98\x9d\x1e\x29\x9f\xe7\x23\x25\x54\x30\x5b\xde\x21\x15\x3e\x7e\x84\x18\x1a\xfc\xc4\xc3\x63\xb7\xcf\xfe\x09\x00\x00\xff\xff\x1f\xbb\x96\x76\xec\x12\x00\x00")

func init() {
	err := CTX.Err()
	if err != nil {
		panic(err)
	}

	var f webdav.File

	var rb *bytes.Reader
	var r *gzip.Reader

	rb = bytes.NewReader(FileCommandTfTmpl)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "command.tf.tmpl", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(f, r)
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	rb = bytes.NewReader(FileDNSRecordTfTmpl)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "dns_record.tf.tmpl", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(f, r)
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	rb = bytes.NewReader(FileInfraTfTmpl)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "infra.tf.tmpl", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(f, r)
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	rb = bytes.NewReader(FileRemoteFileTfTmpl)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "remote_file.tf.tmpl", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(f, r)
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	rb = bytes.NewReader(FileScriptTfTmpl)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "script.tf.tmpl", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(f, r)
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	Handler = &webdav.Handler{
		FileSystem: FS,
		LockSystem: webdav.NewMemLS(),
	}

}

// Open a file
func (hfs *HTTPFS) Open(path string) (http.File, error) {

	f, err := FS.OpenFile(CTX, path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// ReadFile is adapTed from ioutil
func ReadFile(path string) ([]byte, error) {
	f, err := FS.OpenFile(CTX, path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, bytes.MinRead))

	// If the buffer overflows, we will get bytes.ErrTooLarge.
	// Return that as an error. Any other panic remains.
	defer func() {
		e := recover()
		if e == nil {
			return
		}
		if panicErr, ok := e.(error); ok && panicErr == bytes.ErrTooLarge {
			err = panicErr
		} else {
			panic(e)
		}
	}()
	_, err = buf.ReadFrom(f)
	return buf.Bytes(), err
}

// WriteFile is adapTed from ioutil
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := FS.OpenFile(CTX, filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// WalkDirs looks for files in the given dir and returns a list of files in it
// usage for all files in the b0x: WalkDirs("", false)
func WalkDirs(name string, includeDirsInList bool, files ...string) ([]string, error) {
	f, err := FS.OpenFile(CTX, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	fileInfos, err := f.Readdir(0)
	if err != nil {
		return nil, err
	}

	err = f.Close()
	if err != nil {
		return nil, err
	}

	for _, info := range fileInfos {
		filename := path.Join(name, info.Name())

		if includeDirsInList || !info.IsDir() {
			files = append(files, filename)
		}

		if info.IsDir() {
			files, err = WalkDirs(filename, includeDirsInList, files...)
			if err != nil {
				return nil, err
			}
		}
	}

	return files, nil
}
