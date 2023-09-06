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
			// write its contents, and then (atomically) rename it over the destination.
			f, err := os.CreateTemp(parent, "TMP-swanky_sccache_proxy-*")
			if err != nil {
				log.Panicf("Unable to open temporary file in %q: %s", parent, err)
			}
			// This will fail once we've renamed f. But that's fine.
			defer os.Remove(f.Name())
			defer f.Close()
			_, err = io.Copy(f, r.Body)
			if err != nil {
				log.Panicf("Error copying into file %q: %s", path, err)
			}
			err = os.Rename(f.Name(), path)
			if err != nil {
				log.Panicf("Error renaming %q to file %q: %s", f.Name(), path, err)
			}
			// Sccache doesn't like a 204 response (which is proper for an empty body)
			w.WriteHeader(200)
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
