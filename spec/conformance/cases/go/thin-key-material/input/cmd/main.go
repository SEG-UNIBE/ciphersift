package main

import "example.com/app/srv"

func main() {
	var s srv.Server
	s.SetHostKey(nil)
	srv.LoadOnly(nil)
	srv.KeyID(nil)
}
