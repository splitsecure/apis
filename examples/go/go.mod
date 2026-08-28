// Examples are their own module so the apis root module does not take on the
// SDK's cryptography dependencies.
module github.com/splitsecure/apis/examples/go

go 1.25.0

require github.com/splitsecure/apis/sdk/go v0.0.0

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/splitsecure/apis/sdk/go => ../../sdk/go
