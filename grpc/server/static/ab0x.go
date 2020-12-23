// Code generated by fileb0x at "2020-12-22 13:49:02.250777674 -0500 EST m=+0.001944951" from config file "assets.toml" DO NOT EDIT.
// modification hash(a0897b91589109ac452628bfc7996afe.963594ba69d0273dac33db44d8c13043)

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
type HTTPFS struct {
	// Prefix allows to limit the path of all requests. F.e. a prefix "css" would allow only calls to /css/*
	Prefix string
}

// FileServiceKey is "service.key"
var FileServiceKey = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x6c\xd7\xb5\x12\xb4\x08\xb3\x80\xe1\x9c\xab\xd8\x9c\x3a\x85\x5b\xb0\x01\xee\x30\xb8\x64\xb8\x0d\xce\x60\x57\x7f\x6a\xbf\xdd\xf0\xef\xb4\x93\xae\xae\x27\x79\xff\xef\x9f\xe1\x44\x59\xb5\xfe\x72\x3d\xf6\xaf\x8f\xab\x86\xac\x2f\xfe\xa5\x8b\xc9\x9f\x0d\x60\xaa\xaa\xa6\x37\x2a\xc7\xb2\x3a\xcf\x36\x22\xbb\x20\x42\xf9\x5d\xca\x10\xa7\xd3\xd4\xf7\xfd\x26\x95\x33\x8b\xf1\x08\x1c\x37\xb4\xd5\x28\xea\xc1\x08\xb2\x91\x98\xec\xfb\xa3\x62\x42\x6c\x4b\x1e\xc0\xd6\xc9\xcc\x88\x66\x06\x3b\x2b\xcc\x5b\x52\xea\x68\x57\x1b\x40\xc2\x12\x17\xa0\xfe\x0a\xf4\x05\x9d\x69\xfc\x7d\x13\x35\xe1\x16\xf1\x2c\x1f\x72\xaa\x7b\xbf\x5a\x5d\x22\xc7\xf4\xd7\x81\x28\x06\xb0\x39\x92\xdb\x8e\xbd\xd5\x28\xa2\x8e\x9f\x3e\x66\xbe\x2c\x85\x1d\x10\x29\x7e\x70\x4d\xcb\x4c\x6b\x96\x22\xd8\x6a\x98\xa0\xf6\x63\x79\x1d\x69\x84\x53\xd6\x30\xb2\xa8\xbd\x17\xa7\xac\x69\xea\x05\xf0\xcd\xe1\xd1\xc9\x3b\xd5\xba\xd8\xba\x82\x7d\x73\xbf\x95\x18\x0f\x9b\xd3\xcf\xd0\x8f\x2e\x87\x96\xe8\x96\x4c\xd0\xa1\x93\xbc\xdf\x19\x87\x8f\x3b\xe3\xb8\x25\x74\x6c\xb2\xf3\xf4\x56\x43\xbf\x31\x20\x23\x7e\xfb\x92\x42\x77\xd1\x0c\xaf\xae\x2c\xb5\x55\x0d\x62\x58\x82\x75\x7c\x98\x85\x86\x9d\xf0\xba\x93\xf3\x04\x99\x9f\xf2\x9e\x09\xaf\xfc\x6c\x76\xe3\xa2\x49\xec\x96\x45\x80\x5e\xe7\x61\x18\x80\x58\x52\x3f\x43\xc0\x73\xd5\xa4\x50\x97\xf7\xe0\x05\x9f\xa5\xa5\x50\xbf\xd3\xb4\xfa\x13\xe1\xba\xe8\x88\x43\x4f\x31\x48\xb8\xeb\x20\xff\xbd\xcc\xde\x30\x47\x52\x96\xdd\x40\x38\x92\x4c\x60\x29\x20\x99\xce\x02\x1d\xf0\xc7\x76\x58\x39\x6f\x2f\x2a\xb3\x70\x63\xfe\x20\x21\xb3\x27\x66\xb6\x1f\x1b\xeb\x50\x95\x0e\xd6\xb7\x1d\x30\x0f\xd6\x43\x47\x7b\x33\xb2\xe4\x43\xc1\x16\xc2\x3c\xa8\x17\x06\x60\xc2\x5e\x1e\x5a\xa4\x21\x24\x1c\x6c\xa8\xb1\xbd\x82\x54\xdb\xdc\x91\x19\xab\x1c\xbb\x31\x9c\xdc\x99\x8c\x8e\x7d\xc6\x4e\x58\xd5\x48\xb1\x8f\x9e\x7f\x39\xb5\x81\x5d\x3a\xf4\x09\x3a\x48\xe4\x1d\x60\x60\x61\xe2\x45\xd0\xd2\xf4\x96\xf4\xcc\xf5\xbc\xbe\xf0\xf9\xcb\x7f\x18\xc8\x12\xf5\x18\x7b\xf0\x6f\x60\x7c\xfd\x1d\xeb\x2f\x54\x47\x55\x59\xed\xbf\xc5\xd6\x36\xa4\xd9\xa4\x0f\x6d\x96\x4d\xf6\x03\x4e\x98\x5b\x2a\x74\xa4\x71\x94\x46\xd6\x66\xfe\xb2\x26\xc4\xc2\xfb\x0b\xa6\xca\x6d\xb0\x49\xa9\x0d\x45\xd8\xf8\xb9\x6c\x1f\x25\xcd\x73\x0e\x21\xf2\x98\x3f\x2e\x7b\x46\x7c\x90\x4e\xe4\x10\x2f\x05\x7c\xb2\x82\x45\x39\x1a\x5d\x7f\xaa\x1f\x8a\x23\x29\x5e\xbf\x2d\x72\xdc\x1b\x44\x21\xa4\x3d\x51\x02\xf5\x17\x17\xa1\x5f\x7a\xbd\x18\x43\x73\xd0\x56\xf6\x5b\xe3\xee\xe3\xdb\xb4\xc9\xb3\x97\xc8\x02\xac\xf3\x2f\xe1\xa9\x5b\xc8\x69\xc3\x15\x7e\xe5\xd2\xe1\xf3\xc3\x23\x4e\x00\x5b\x24\x2c\x94\x24\xdc\x7a\x31\x8a\x2d\x77\xe2\xe8\x8d\x70\x1d\x0d\x03\xa7\x54\x06\x91\x08\xab\x3f\xaf\x38\x00\x19\xa1\x0b\xab\x9a\xca\x6b\x97\x1c\x0c\x0c\xa7\x9f\x89\x70\xda\x01\xe7\x9d\xde\xce\x7b\x12\xce\x0b\x3a\xe6\x7c\x08\x8f\x5c\x68\xb4\x48\x3f\x30\xed\xbd\xea\xd4\xb0\xf9\x71\xe5\xa5\xa2\xc5\x87\x04\xf2\xad\x3b\x8d\xcc\xb7\xd6\x9f\x3a\x70\x7b\xe5\xd5\x4a\x45\xe8\xa0\x53\xcc\xaa\x2a\x1a\xfb\x2a\xa9\xcf\x75\x22\xdb\xe7\x45\x63\xd8\xd4\xf1\x73\xa6\x48\xe9\xb0\x90\x5e\xb2\xf3\x45\xac\x85\x2c\x07\x7e\x34\x3c\xa2\x21\x84\xc2\x94\x79\xdc\xf1\xd7\x05\x45\x7d\x34\xaa\x46\x82\x74\xe8\x19\xc7\x58\x90\x46\x7c\x46\x52\xa4\xc2\x27\x55\x33\x0d\x74\x1d\x29\x7d\xb9\xdf\x1e\xee\x84\xde\x19\xbe\xa5\x0f\x2c\xeb\xa0\xad\xe7\xe7\x92\x36\x31\xad\xb0\xc1\x7f\x2d\x2b\x0b\xd9\x98\x82\x55\x7f\x3b\x0c\xb7\x0d\x35\xab\xc0\x15\x08\xb6\x3b\x97\xcc\x88\xbe\x15\x1c\xd8\xd0\xe5\x0d\x7a\x94\x06\x07\xd3\xed\x0b\xc0\x9d\x89\x53\x5f\xe9\xbd\x3b\x8a\x67\x85\x8e\x06\x21\x61\x5d\x93\x2c\xcd\x70\x9b\xe4\xe9\xc8\xa9\xc1\x1e\x44\x02\x5d\xe6\x12\xaf\x9f\x1b\x89\xce\x3c\x17\x32\x4d\x95\x7e\xf7\xbd\xea\x2e\x95\x01\xea\x4f\x59\x3d\x11\x94\xf5\x15\x23\x68\xe1\x4f\x45\x03\xf8\xf6\xc5\xbb\xb3\x08\x8a\xba\x78\xc2\x56\x3d\x5f\xb4\xef\xa8\x7e\x6c\xb9\x23\x7b\x5e\xca\x72\x93\x4a\x35\x42\xc6\x11\x2d\xb2\x6a\xba\x02\xb8\xee\x0a\x1e\x9b\x1f\x67\x95\xb6\x10\xc2\xa6\x55\xb7\x59\xb0\x8e\x54\xa4\x6d\xff\xe8\xbd\xbf\x14\x56\x4e\xc8\x1b\xad\xa7\x1d\x93\x76\x1d\x1e\x6e\xfb\x46\xc4\x63\x68\x32\x66\x85\x7f\x65\x0c\x05\x98\xb8\x8d\x2b\x93\xad\x99\xf2\x3a\x76\x50\x16\x17\x8e\x15\xd2\x6d\x95\xd1\x3b\xb2\x7a\x64\xcd\xa5\xee\x50\xd4\xc7\x40\xd3\x17\x89\x7c\x3b\xfa\xfa\x52\x2c\xd4\xe2\x6f\x70\xd6\xc1\xe9\xf3\x8b\x05\x26\x5c\x7a\x6b\x9d\x8f\xfa\xd3\x2a\xd9\x88\x8c\xa2\x72\x69\x8f\xa1\xb5\x47\xbf\xfb\xa0\xd8\xb7\x5f\x4a\x5b\x7f\x88\x94\xc5\xb5\x09\xca\x79\xf7\x53\xfd\xbc\x9f\x76\x38\x1c\x68\xe9\x21\x6e\x19\x1d\x40\x17\x45\x28\x36\x51\x70\x99\x93\xad\x75\xf8\x27\x43\x3f\x85\xfc\x0b\x4c\xe2\xc5\x02\x86\x8e\x9f\x8f\xf1\xae\x5e\xdb\x17\xcc\x7a\x4c\xa2\x08\xc1\x37\x2e\xf2\x4d\x23\x72\xac\xb5\x23\x88\xb2\x6f\x80\x8c\x47\x42\x66\xee\x9f\x18\xc4\xcf\x22\xba\x5c\xc2\x64\x0c\x2c\x55\xbe\xb9\x56\x59\x9a\xde\x49\x16\x69\xdd\x30\x8d\x23\x43\x61\xcd\x30\xd1\x37\x1e\x73\xf1\x95\x3f\x09\x68\x2b\x27\x10\xcb\x6a\x80\x45\xcb\x52\x5e\x41\xf9\xcb\x45\xf6\x3e\x4b\x0d\xa8\xb7\xd3\xc7\x0d\x2d\x0f\xc1\x2d\x8a\xca\xeb\x6f\xe6\x3c\xf8\x14\x09\x12\xd4\x12\x96\xdd\x4f\xf2\xcb\x57\x7a\x28\x5e\x9d\x19\xb2\xc6\x3f\x17\x14\x4c\xfe\x61\xad\x0c\x2b\x57\x6e\x2b\x21\xa9\xba\x32\x15\xf6\x9f\xdf\x93\x8a\xcb\xda\x40\x4e\xa9\xca\x97\x7d\x51\x6f\xb9\xb8\xf6\x2f\x86\x6a\x88\xb4\x70\x9d\xb7\x5a\xb2\xfc\x7e\xb2\x83\x44\x31\x40\xb6\xa5\x5f\x49\x3c\xe7\x70\x3b\x13\x3a\x1f\x84\xab\xd9\x5e\x3b\x9c\x58\x6b\x29\xb0\xef\xb4\xd4\x6b\x6a\x7e\x90\xa1\xfb\xa2\xa8\x73\x8f\x73\xcb\x57\x34\x44\xe5\xd0\x90\xbe\xea\x1b\xbd\x6c\x0d\x40\x68\xa2\x19\xec\x43\xa5\x85\xb2\x99\x64\x36\x9d\x3d\x1d\xd9\x33\xb4\x15\xad\xb1\x50\x36\xe7\x4b\x22\x7f\x85\xae\xf1\xe3\x75\x3d\xe6\x84\x71\xc2\x6b\x16\xaa\xbe\x1a\x72\xdd\x92\xce\xfd\x1b\x31\x60\x86\x4f\x86\x2a\xca\x91\x55\xf5\x8e\x55\xcd\x7f\x3f\x6c\x5a\xdf\xc2\x50\x30\x67\x6f\x3e\x1f\x86\x72\x3a\x97\x6c\xcc\x38\x28\xdd\x73\x3f\x2e\xfb\x5c\x02\xd6\xc1\x43\x77\x56\xc5\x37\x2a\x80\x24\xb3\xd4\x95\xaa\xd8\x9a\xf1\xef\x15\x99\x39\x28\xbb\xe0\x6e\xc5\x32\x33\x6f\x4d\x67\xc8\xe7\x12\xb1\x73\x16\x71\x57\x33\xfe\x89\x5b\x61\xaa\xfa\x9d\x89\xdf\x14\x67\x1a\x0e\xb2\xcb\xca\x45\x00\x5d\x23\xa2\x9c\xf6\x86\x2b\xc5\x3e\x2c\x58\x4b\x99\x46\xbe\x7b\xcc\xa2\xf3\xcd\x84\x23\xab\x0b\xbc\x0b\x4e\x0f\x16\xb4\xe2\x20\xd7\x7d\x65\xb2\x3f\xbc\x97\x6e\x16\x7b\x06\x0a\xa4\x13\x87\xdf\x01\x57\x9e\xce\x50\xe9\xc1\x55\x91\xbf\xfb\xc6\xd6\x29\xff\x6b\x5c\xb7\x0f\x15\x90\x80\xf6\xd5\xd2\x56\x14\xa7\x72\x57\x15\xbd\xa0\x10\xaf\xb2\xfe\x3d\x39\xb8\x49\x02\x87\x2a\xd4\x38\xd6\x8e\xd5\x00\x5f\x2d\xf2\x2f\xb6\x88\xa1\x99\x56\x33\xa4\xcb\x8f\x8f\xb4\x6e\xfc\x0b\x95\x3e\x48\xc5\x32\x09\x19\x25\xff\xd9\xc8\xca\x5c\x13\xe9\x87\x9a\xc5\xd3\x5b\x56\xda\xc5\x23\xfc\xc8\x23\x91\x99\xc6\x04\x9c\xe6\x6f\x66\xda\x22\x30\x14\x55\x43\x0f\x9f\xfc\x5c\x5a\xdb\xcb\x3f\x84\x6d\x41\x93\x84\xec\xaa\xea\x03\xf9\x69\x77\xaf\xa0\xff\x23\xac\x9e\xb2\xfc\xa8\x95\x31\x6b\x4a\x29\x10\x23\xa0\xc2\x03\x7b\x22\xd1\x37\x79\x2f\x72\x21\xc5\x6d\x31\x08\x6b\x71\x71\xc8\x44\xf3\x39\xc9\x64\xfb\xdd\x29\xf9\x54\x83\x47\x21\x1f\xa6\xbc\x32\xd2\xba\x92\xb4\xe9\x23\x7f\xbd\xa3\xca\x5e\x4b\x1e\x68\x5e\xd3\x38\x1a\x92\x63\xe7\x1b\x5c\x88\x86\x98\x6c\xe1\xe2\xeb\x28\x74\xee\x6f\xfe\x98\x6a\xe9\x58\xa0\xd7\x25\xc9\x6c\x7d\xd5\xf2\x86\xf5\x74\x65\x4e\xd2\x46\xf5\x4a\xfb\x1a\x12\x0c\x17\x21\x80\x29\x6a\xf8\x55\x06\x2c\x1f\x1a\x8a\x9f\xb8\x28\x41\x5c\x88\x9a\x8e\xc3\xbd\xf6\x7a\x3b\xcb\x27\xd7\x4e\x93\xe7\x91\x12\x07\x55\xa7\x03\x8f\xe2\x59\x89\xd0\x06\xa5\x3d\xfb\xfa\x2f\x72\xf7\x08\x90\x1d\x79\xef\x2c\x9b\xe8\x4b\x32\x3d\x70\x88\xea\x0d\x8f\x54\x16\x3d\xc4\xa1\xde\x6d\x32\x95\xf4\x64\xe1\x45\xa1\x0c\x82\xaf\x4c\x8d\xf4\x65\xcf\x24\x9e\xff\x2c\x2b\x85\x9b\x83\xa0\x56\xe5\x09\xa8\x76\xae\x97\xe7\x50\x51\xed\xde\x4b\x0b\x68\xd9\xc3\x42\xe1\x3d\xb9\x5c\x24\x6e\x82\x32\xdf\x1f\xba\x01\x21\xd8\xcc\xb3\x81\x87\x7d\xa5\xc6\x36\x4d\x3f\x18\x68\x21\xa3\x9f\x0e\x09\x7d\x37\x07\xaa\x12\x72\x09\x65\xf8\x8f\x30\x2f\xaa\xfb\x25\x4d\xb9\x8d\x64\x2b\xda\xd1\x68\x6e\x46\x26\x11\xb1\x41\x97\x2f\x56\x63\x98\x31\x31\x52\xdf\xc5\x1e\x95\x2c\x43\xd4\x7b\x9a\x46\x3e\x06\x52\xe6\xb7\x2b\x86\x41\xb1\x1e\x44\xd8\x7a\xdc\x58\xd2\xba\x9b\xbc\xdf\xf3\x7c\x2e\x1e\xfe\x35\x5d\x4e\xc1\xf0\xa8\x41\x8f\x03\x03\xa6\x52\x9d\xaf\x13\xbb\xab\x4a\xfc\x6b\x1d\x14\x6e\xfb\xd7\x06\x1c\x5a\x7e\x53\x6b\x9d\xf0\xc3\x7a\xe6\x55\xc6\x59\x4c\x3b\x38\x90\x21\xe6\xdc\x6b\x2f\x44\x3a\xec\x67\xf5\x39\x0b\xef\x75\x52\x3f\x7b\x50\xcb\x94\x9a\xdc\x67\x7f\xe9\x1b\xbd\x33\x22\xd3\x21\x80\x57\xcc\xbf\x5c\xcf\x2b\x7e\x00\x92\x4d\x3f\x15\xde\x26\x44\xe0\x08\x1d\xc7\x8e\xd8\x72\xa1\x48\x53\x38\xfc\x76\x6a\x55\x65\x6e\xf0\xab\x77\x6a\x6c\xed\x13\xcb\x5a\xa1\x3b\xd3\x4e\xe4\xc7\x66\x03\xe9\x80\x3b\xf4\xbc\x8b\xda\x79\xdd\xab\xcd\x39\x4c\x3d\x99\x5a\x48\xef\x21\xf4\x88\x6d\xa2\x0c\xc3\xa8\x4c\x03\xdb\x52\xf3\xbe\x55\x42\xdb\xfe\xc8\xc4\x4a\xe3\x44\xee\x5b\x02\x41\x16\x63\xd2\x81\x82\xb8\xcc\x98\xd4\x91\xe7\x03\x07\xdf\x4c\xb0\x12\x56\xdc\x20\x4d\x85\x07\x02\xd3\xbc\x7c\xba\xb6\xe0\x0f\x61\x56\xa7\x53\xe5\x36\x9d\xaa\x52\x92\xc1\x98\x3a\x42\xbe\x59\x0d\xc5\x6e\x0e\x98\x88\x28\x73\x69\x0a\x0c\xf2\x13\xb1\xe9\xce\x0a\xdb\x06\xb4\x16\x98\x14\x09\xd4\x5a\x38\x46\x11\xc3\xa4\x03\x61\xe1\x6c\x2b\x21\x70\x84\xc7\x4a\x9c\x95\x76\x4f\x6e\x0b\x67\x49\xe1\xe7\x14\x02\x9e\xd5\x30\x5d\x36\xf1\xcc\x54\x1d\xa2\x49\x36\x29\xdc\x4f\x50\x0f\x7b\x8a\x8f\xca\xb5\x8b\x9d\x12\xba\x5b\x07\x39\x82\xb9\xf9\xaf\x3b\xdd\x3b\x50\xef\xba\x4f\xef\x4d\x1c\x30\x0e\xcb\xbc\x98\x06\x22\xbc\xca\x33\x59\x34\xad\x0e\x76\x72\x3f\x2b\x26\x46\xa6\x52\x90\xb1\x40\x89\x1c\x1b\x6c\xad\x8b\x66\x56\x98\x35\xdc\x29\x14\x44\x70\x87\xd9\x8d\xfd\x5b\x0d\xd2\xda\x4c\x36\x93\x1d\x9c\xbd\x01\x18\x7c\xe6\x54\x4a\x9e\xa3\xe1\x8a\x4f\x83\xe2\x2b\x08\x9a\x85\x0e\x07\x4a\x8c\xf3\xac\xaa\xb0\xf1\xb0\x4b\xe9\x8f\x5e\x4d\x48\x48\x23\x3b\x1f\xb3\xf6\x51\xb7\x95\x3c\xe3\x25\xd8\x53\x12\x65\x80\x71\xa3\x9a\x37\xb0\x3f\xad\x00\x69\x98\x87\xad\x8f\xa0\x07\x23\x4f\xc1\x4d\xdb\xc0\x68\x90\x79\xcc\xb7\x38\xba\xc3\x89\xf4\x86\xca\xde\x7d\x5d\x3d\x46\xaa\x7a\xf0\xe6\x3c\xf7\x49\x35\xf6\xef\xbf\x81\x3f\xd9\x21\x5a\xc2\xff\xce\x91\xff\x0f\x00\x00\xff\xff\x58\x15\x98\xb6\xaf\x0c\x00\x00")

// FileServicePem is "service.pem"
var FileServicePem = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x6c\x95\xb9\xce\xbb\x4a\x12\xc5\x73\x9e\x62\x72\x6b\x04\x98\x3d\xb8\x41\x37\x34\x7c\x2c\x0d\xc6\xec\xce\xd8\x77\x1b\x0c\x06\xcc\xd3\x8f\xfe\xdf\x24\x73\x35\xf7\x24\x25\xfd\x8e\x74\xaa\x92\xd2\xf9\xf7\x1f\x41\xa4\xe9\xf6\xbf\x64\x74\xf7\x75\x55\x97\x81\x8f\x7e\x29\x81\x75\x5d\xb5\x3a\x59\x06\x47\x5a\x83\x5d\x87\xa0\xd6\x03\xad\x0f\x82\x80\x8c\xed\xb9\xe9\xac\xd1\xaf\xb4\x75\x17\xb4\x28\x97\x9e\xf5\xd9\xef\x8a\x9b\x18\xe6\xeb\xa1\x37\x5b\x6e\x03\x17\x59\x04\x74\xc1\x6e\xf9\xc8\xc2\xa0\xd7\x00\x1d\x20\xd8\x60\x39\x0c\xf1\x21\x9f\xc0\x80\xb5\x1d\x42\x50\x63\xd0\x73\x26\xbe\xa3\x5d\xd9\x13\x25\x74\x5d\x53\x01\x8d\xe2\x7a\x7b\xed\x45\x5c\x47\x58\x1d\x28\xd5\x9d\xfa\x62\x05\x7d\x71\xa7\x1f\x8e\xe2\xb2\x58\x29\xd2\x5f\xe6\xff\x9d\x61\xf4\xbf\xc1\x89\x0f\x86\xd0\x27\xb0\xbb\xec\xb2\xfb\x9b\xac\x2b\xc0\x70\xbc\x0e\xf9\x18\xa2\xdf\x6b\xe4\x7a\x37\x43\x2d\x3c\x0b\xf9\xbf\xdb\xac\x0e\x79\x18\x82\x5f\x0f\xec\xbb\x91\x69\x52\x47\x24\xd1\xf1\xca\x18\x9b\xc2\xba\x2e\xeb\x1d\xb0\x61\xdd\xcf\x4d\xdf\x6a\xd2\x4e\x41\xe0\x22\x15\x00\x47\x06\xb5\x08\xfe\xf8\x72\x6d\xca\xa0\x46\x60\xa2\x95\x62\x98\x8a\x90\x15\x1f\x0f\xc2\xf7\xfd\xfa\xa1\xa5\xb6\xe4\x71\x2c\x6b\x19\xb3\x95\x57\xbd\x15\xa4\x23\xf7\x74\x8e\x9b\xce\x28\xb1\xa3\x7a\xa0\x4a\x5e\x12\xc2\x29\xe5\xce\x94\x6c\xab\x0f\xd7\xd8\x9b\x80\x54\xa6\x38\xbf\x98\xc4\xa9\x88\x3b\xb9\x3d\xe2\xe1\x4c\xf4\x04\x4e\x68\x2b\xbe\xfc\xb3\xea\xfc\x72\xbe\x73\x19\x63\x9e\x2e\x29\x48\x0e\xe4\xe1\x7b\x5d\x1a\x43\xe0\xaa\xf8\xdb\xc5\xd2\x00\x04\x66\x25\x79\x74\x63\x0d\xc2\x48\xb1\xfd\x52\x23\xca\xae\xa5\xa0\xf2\x63\x6d\x1e\x45\x1a\xfe\xcc\x61\x64\x0b\x4b\x87\x9e\x69\x5d\x57\x93\x8f\xfb\xaf\xc9\x1f\x0f\xa3\x8d\xed\x3d\x58\xde\xf7\xa1\x44\x71\xff\x76\xbb\x17\xf9\x21\xc4\xa2\x6f\xb8\x76\x4a\x15\x93\xdc\xf8\xe3\x7c\xb1\xd4\x7a\xa4\x10\x4e\xa1\xeb\xf0\xad\x67\x36\xc6\x75\x88\x35\xda\x6f\x4e\x5e\x69\x77\x51\x92\xf5\x19\x08\xef\xb2\xa6\x2d\x5b\xb1\xd7\x9b\x34\x11\x22\xe5\x86\xfb\x91\x6c\xdb\x45\xfa\xfc\x9c\x5b\x22\xff\x7c\x1c\xf0\x86\xd1\x13\xb5\xd3\xa4\x90\xa7\xfb\x95\x24\x6e\x7a\xf8\x29\x7d\xd9\x66\x43\x0d\x4d\x6d\x09\xce\xcb\x77\x6a\x84\xab\xdf\x1a\x46\x45\xdc\x22\xd6\x44\x2e\xea\x3b\x41\xa2\xc3\xc5\xbc\xc8\xc3\x8e\x3b\x0b\x8f\xbc\xa6\xdd\x03\x65\x4d\x52\x05\x08\xc9\x73\xcb\xaf\x3d\xfb\x75\x5c\xa0\x65\xcd\x2e\xa4\x36\x6b\xbd\x6e\x74\x28\x2d\x09\x26\xd2\x65\x7d\x03\x57\x28\xcd\x4b\x75\x38\x81\xf4\x65\x3a\x72\x6d\x0e\x49\x53\x7d\x32\x78\x87\x94\x7c\x31\x73\x0b\x53\x5e\x16\xda\xbc\xa5\x24\x90\xb2\xf4\xd8\x99\x2f\x42\x53\x1f\x11\x8e\x75\x08\x88\xb7\x04\xb5\x16\x4b\x26\x73\x1b\x5b\x65\xd6\xa3\x1f\x67\xed\xe4\x13\xea\x35\x75\x17\x43\x9f\x13\x83\x44\x5b\x24\x4a\x79\xca\xe8\x62\x1b\x66\xc3\x7b\x78\xde\xf6\x81\xda\x3e\xd9\x87\xb9\x00\xae\x22\xc6\xd8\xa3\x3e\xbd\xe4\x9b\xe7\x58\x0d\x64\x15\x95\x45\xb9\x7c\x26\xc7\x78\xd3\xf5\x5b\xbd\x89\xb8\xa8\xd3\xcf\x46\xc1\xa9\xbc\x8e\x22\x7b\x15\xe9\xb9\x7e\x0d\x00\x93\x80\x5a\xce\xcb\xe3\xe7\xb0\x08\x90\x14\x46\x9f\x87\xb5\x9f\x69\xce\x5a\x88\x32\x74\x39\x24\x33\xfe\x38\x2d\x29\x77\xa3\x5b\x04\x69\xef\xe1\xf3\x25\x85\xb4\x68\xbc\xfb\xcf\xea\x2b\x40\x5e\x90\xcd\xc3\xe6\xc7\xa5\xa6\x7f\x38\x42\x5d\x92\x9f\x40\xff\xc4\x79\xe8\x17\x5e\x87\x62\xf2\x15\x34\xa5\x73\x56\xec\xfd\xeb\x3b\x22\x96\xc1\x8e\x00\x48\xf1\x8e\x65\x76\xb7\x40\xa2\x84\x77\xea\x0e\xe5\x60\xd7\x59\xfd\xef\xbf\xd0\x1c\xe0\x9f\x04\x9b\xfd\x4e\xfe\x99\x18\x50\x9a\xec\xcd\x9a\xa7\x67\x8c\xe2\x22\x28\xef\x01\x00\xac\x2e\x13\xc0\x95\x13\x6e\x55\x43\xe7\x76\x7d\x8c\xb1\x6c\x47\xac\xb4\x27\xed\xfa\x83\x42\x1b\x65\x89\x7f\xb5\xba\xb3\x19\xd6\xa2\xf7\xd3\x2f\xbc\xde\xc7\x6c\x9a\x5e\xfe\x18\x39\x02\x1c\xb6\x4b\xaf\xf5\x13\x21\x39\x27\x9f\xf4\x7c\xd9\xf1\xec\xa8\xf2\x00\xfe\x94\x96\x1d\x6d\x4c\xf4\x39\xf7\x61\xae\x9f\x5b\x89\x23\x37\xf1\x99\x0d\xcd\xcb\xc6\x26\x6a\xee\xdb\x4a\x12\x1b\x55\xba\xdc\xd0\xce\x6d\xe3\x4e\x30\x01\x6a\x11\x6d\xe5\x57\x36\x50\x0d\xf3\xad\xa3\x5b\x73\xfb\x81\x15\xbb\xd1\x93\xde\xdd\xea\xb6\x30\x52\xaa\x54\xeb\x2c\x91\xb8\xc5\x69\x1d\xbc\x42\xf5\x1d\x86\x0c\xf0\x40\x98\x50\x61\x51\x11\xaf\xb4\x0b\x46\x0e\x1b\x61\xbd\x42\x5c\x8b\x64\xac\x18\x38\xb0\x27\xd6\xe6\x8d\x60\xb0\xab\x53\x85\xb4\xf8\xbd\xe7\xc8\x49\x84\xf7\x57\xf9\x64\xa6\x19\x07\x9f\x2c\x8d\xe6\xa2\x96\x5b\xe6\x55\x10\xeb\x93\x56\x9a\x30\xe8\x92\xbb\xd1\xe6\x0f\x31\x5c\x2e\x51\x21\x2b\xdc\x65\x6f\xf3\xcd\x98\xfa\x07\x47\x5f\x2e\x53\x72\xf6\x26\x97\xae\x53\x93\x31\xe0\xf9\x9e\x31\xb3\x93\xdd\xe0\xc6\x42\xe3\x7b\xc4\xaa\x4c\x98\x3a\x5e\x03\xa2\xa4\xf9\x11\x87\xd8\x15\xc8\x61\x3f\xac\xb9\x2c\xdd\xb7\x63\x46\x72\xa7\x17\xea\x9d\xbf\x3d\xf2\x70\x4d\xb5\xfc\x31\x84\x0a\x78\xe4\xc1\x8d\x53\x5a\x66\xae\xc1\xaa\x12\xd5\x2c\xea\x8e\x2e\x79\x73\x1c\x29\xd9\xb4\x36\xfa\xed\x76\xe7\x37\x71\xf6\x04\x4d\xf3\xe9\x34\x43\x26\x4d\x0a\xd7\x83\x9e\x0d\x83\xdb\x3c\xa6\x8b\xf3\x6b\x5a\x1e\x27\x98\x79\xbf\x4c\x4b\x27\x24\x7e\xf6\x76\x9c\xca\x08\x1e\xeb\x7b\x3c\xc4\x16\xc0\x49\xd0\x96\x54\x3a\xd5\xb9\xcd\x2a\x5d\xe8\x4a\xea\xd6\xf0\x9d\x7d\x70\x12\xb3\x66\xa7\xba\x90\x6c\x74\xa5\x32\xf0\x94\xe3\xf6\x72\x99\xc5\x82\xd0\x8b\x3d\x9b\xcc\x94\xa4\x6f\x16\xa9\x68\x49\xdf\xcf\x48\x7b\xe6\xfc\x26\xe0\xc7\xec\x49\xbe\x7e\xdc\xbd\x8c\xa5\x51\xd9\xc4\x37\xea\xfa\xd6\xc2\xe2\xc2\xce\x6a\x44\x07\xca\x6e\x4e\x02\xa0\x15\xc2\x5d\x8e\xba\x8f\x9e\x70\x67\xa4\xef\xeb\x0b\x99\xd4\x7a\xaa\x27\xfd\xd5\xed\x92\x9d\x98\x7a\x49\xb8\xb9\x41\xf6\x5a\x34\xfd\xf1\xad\x4d\x4d\xb1\x16\x21\xe1\xd3\xf8\x1d\x5c\x93\xe6\xb3\x8d\x5c\x40\xe8\xb2\xb3\xd6\xa4\x9e\x7f\xf8\x74\x00\xbd\x43\x33\x12\xb8\x92\x9b\x2f\x33\x65\xe6\x30\xf9\x58\x1c\x9a\xaa\x0f\xae\x56\x1f\x99\x5f\x0f\xee\x5f\x7f\x11\xbf\x8d\x88\x6c\xe5\xff\x5b\xf2\x3f\x01\x00\x00\xff\xff\xd7\x2c\x08\xa1\x42\x07\x00\x00")

func init() {
	err := CTX.Err()
	if err != nil {
		panic(err)
	}

	var f webdav.File

	var rb *bytes.Reader
	var r *gzip.Reader

	rb = bytes.NewReader(FileServiceKey)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "service.key", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
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

	rb = bytes.NewReader(FileServicePem)
	r, err = gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	f, err = FS.OpenFile(CTX, "service.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
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
	path = hfs.Prefix + path

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
