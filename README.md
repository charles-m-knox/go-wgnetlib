# wgnetlib

wgnetlib (Wireguard Net Lib) is a Go library that allows generating complete networks of Wireguard peers.

For example, if you wanted to have a set of peers that all exist under `192.168.5.0/24`, this library will allow you to quickly generate a private & public Wireguard key for each peer on the network.

## Usage

### Go library

`wgnetlib` can be used as a Go package like this:

```bash
GOSUMDB=off GOPROXY=direct go get -v gitea.cmcode.dev/cmcode/wgnetlib@latest
```

Then:

```go
package main

import (
    "gitea.cmcode.dev/cmcode/wgnetlib/gen"
)

func main() {
    conf := gen.Configuration{
		GenerationParams: gen.GenerationForm{
			CIDR:                "10.0.0.0/24",
			DNS:                 "10.0.0.1",
			Server:              "10.0.0.1",
			ServerInterface:     "eth0",
			Endpoint:            "5.5.5.5",
			EndpointPort:        51820,
			MTU:                 1280,
			AllowedIPs:          "0.0.0.0/0",
			PersistentKeepAlive: 25,
		},
	}

    err = conf.Generate(false)
	if err != nil {
		log.Fatalf("failed to generate: %v", err.Error())
	}

    b, err := yaml.Marshal(conf)
	if err != nil {
		log.Fatalf("failed to marshal conf: %v", err.Error())
	}

    err = os.WriteFile("output.yml", b, 0o644)
	if err != nil {
		log.Fatalf("failed to write output to %v: %v", "output.yml", err.Error())
	}
}
```

### CLI

```bash
GOSUMDB=off GOPROXY=direct go install gitea.cmcode.dev/cmcode/wgnetlib@latest
```

`wgnetlib` can be used as a CLI tool, if desired - specify the `-i` flag for fancier terminal output:

```bash
./wgnetlib -i -f output.yml -o output.yml
```

- specifying the `-f file.yml` flag will cause `file.yml` to be loaded on startup and its values will be reused for the next run
- specifying `-o output.yml` will write the output to `output.yml`

## Rough benchmarks

- `/16`:-
  - 65,000 IP addresses
  - ~2GB RAM usage
  - 3.6 seconds
- `/12`:
  - 260,000 IP addresses
  - ~8-10GB RAM usage
  - 15.7 seconds
- `/8` networks and any networks larger than `/12` are currently untested.

## Optimization discussion

- This library is more focused on speed than on RAM usage.
- All operations take place directly in RAM. This is intentional for now.
- In the future, I'd like to experiment with writing the data to disk (via a toggleable option, and another option for gzipping to disk) to allow for using disk space as a resource instead of RAM.
  - However, the `yaml` serializable format may not be the best choice for accomplishing this.
  - When using `wgnetlib` as a library, it may be most desirable to write everything to a `tmp` directory for this use case

## Other notes

- I'd like to eventually offer different file formats, such as:
  - each peer gets its own file (this will be very useful for the above discussion about using the disk instead of RAM)
    - offer gzip/xz compression for each file too
  - sqlite (I formerly wrote this to only work with sqlite so I do have the code elsewhere)
  - json
