module gadgets

go 1.19

require (
	github.com/consensys/gnark v0.0.0-20230315015730-8699eba5710d
	github.com/consensys/gnark-crypto v0.9.2-0.20230314094804-5185eb8c3978
	github.com/rs/zerolog v1.29.0
)

require (
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/stretchr/testify v1.8.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20230213192124-5e25df0256eb // indirect
	golang.org/x/sys v0.5.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace (
	github.com/consensys/gnark => github.com/celer-network/gnark v0.0.0-20230320034321-160790554009
	github.com/consensys/gnark-crypto => github.com/celer-network/gnark-crypto v0.0.0-20230316082432-b8844ef42f30
)
