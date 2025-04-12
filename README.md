[![Go Reference](https://pkg.go.dev/badge/github.com/go-crypt/x.svg)](https://pkg.go.dev/github.com/go-crypt/x)

# github.com/go-crypt/x

Low level library which copies several elements from [golang.org/x/crypto] and [github.com/openwall/yescrypt-go]. For a 
higher level library see [github.com/go-crypt/crypt].

## Intent

This library aims to implement feature parity with [golang.org/x/crypto] except for the following alterations:

- Only crypt functions and functions to support these exist
- Expose more methods
- Adjust existing methods to have better uniformity


[golang.org/x/crypto]: https://pkg.go.dev/golang.org/x/crypto
[github.com/go-crypt/crypt]: https://github.com/go-crypt/crypt
[github.com/openwall/yescrypt-go]: https://github.com/openwall/yescrypt-go
