package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

var bind = flag.String("bind", "", "the address to bind to")
var dataDir = flag.String("data", "", "where to store the data")
var ready = flag.String("ready", "", "If specified write a '1' once the server is up, to indicate that it's ready.")

func handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		e := recover()
		if e != nil {
			w.WriteHeader(500)
			log.Printf("500 internal error: %s", e)
		}
	}()
	method := strings.ToUpper(r.Method)
	if method == "GET" || method == "PUT" || method == "POST" {
		base, err := filepath.Abs(*dataDir)
		if err != nil {
			log.Panic(err)
		}
		path := filepath.Clean(filepath.Join(base, r.URL.Path))
		// TODO: is this secure?
		if base[len(base)-1] != '/' {
			base += "/"
		}
		if !strings.HasPrefix(path, base) {
			w.WriteHeader(404)
			log.Printf("Path %q doesn't start with %q", path, base)
		}
		if method == "GET" {
			f, err := os.Open(path)
			if err != nil {
				if os.IsNotExist(err) {
					w.WriteHeader(404)
					return
				} else {
					log.Panicf("Error reading file %q: %s", path, err)
				}
			}
			defer f.Close()
			filelen, err := f.Seek(0, 2 /*end of file*/)
			if err != nil {
				log.Panicf("Error getting file length of file %q: %s", path, err)
			}
			_, err = f.Seek(0, 0 /* beginning of file */)
			if err != nil {
				log.Panicf("Error rewinding file %q: %s", path, err)
			}
			w.Header().Add("Content-Length", fmt.Sprint(filelen))
			w.WriteHeader(200)
			_, err = io.Copy(w, f)
			if err != nil {
				log.Panicf("Error copying file %q: %s", path, err)
			}
		} else {
			parent := filepath.Dir(path)
			err = os.MkdirAll(parent, 0755)
			if err != nil {
				log.Panicf("Mkdirall(%q) failed with %s", path, err)
			}
			// This is the key part that sccache doesn't do which makes it not safe for concurrent
			// accesses. We want to get a temporary file in the directory we're trying to write,
			// write its contents, and then hard-link it into the right place. In addition, we'd
			// like the temporary file to not have a directory entry, so that if this process
			// crashes, there's nothing to clean up (since an inode that isn't open, with no
			// directory entry will be garbage collected by the OS). Once we've successfully
			// written all of our data to the file, we hard-link it into the correct place.
			// Because the hard-linking operation is atomic, it means that every reader will either
			// see (A) GET(path) does not exist, or (B) GET(path) returns the complete contents of
			// the "last" successful PUT(path).
			// NOTE: that this doesn't fsync or fdatasync, and so might not be fully correct across
			// power loss.
			f, err := os.OpenFile(parent, os.O_RDWR|unix.O_TMPFILE, 0644)
			if err != nil {
				log.Panicf("Unable to open temporary file in %q: %s", parent, err)
			}
			defer f.Close()
			_, err = io.Copy(f, r.Body)
			if err != nil {
				log.Panicf("Error copying into file %q: %s", path, err)
			}
			srcPath := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
			err = unix.Linkat(unix.AT_FDCWD, srcPath, unix.AT_FDCWD, path, unix.AT_SYMLINK_FOLLOW)
			if err != nil {
				log.Panicf("Error linkat-ing to file %q: %s", path, err)
			}
			w.WriteHeader(204)
		}
	} else {
		w.WriteHeader(405)
	}
}

func main() {
	if runtime.GOOS != "linux" {
		log.Panic("Requires linux (for O_TMPFILE)")
	}
	flag.Parse()
	if *bind == "" {
		log.Panic("--bind must be specified")
	}
	if *dataDir == "" {
		log.Panic("--data must be specified")
	}
	l, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Panicf("unable to listen on %q, due to %s", *bind, err)
	}
	log.Printf("sccache disk proxy server is listening on %q", *bind)
	if *ready != "" {
		f, err := os.OpenFile(*ready, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Panicf("Unable to open readyness file %q due to %s", *ready, err)
		}
		defer f.Close()
		_, err = f.Write([]byte("1"))
		if err != nil {
			log.Panicf("Unable to write to readyness file %q due to %s", *ready, err)
		}
	}
	(&http.Server{
		Addr:    *bind,
		Handler: http.HandlerFunc(handler),
	}).Serve(l)
}
