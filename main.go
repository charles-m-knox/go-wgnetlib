package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"

	gen "github.com/charles-m-knox/go-wgnetlib/pkg/wgnetlib"
	"github.com/pterm/pterm"

	"gopkg.in/yaml.v3"
)

var (
	flagInteractive    bool
	flagConfig         string
	flagOutput         string
	flagGzipProcessing bool
)

func parseFlags() {
	flag.BoolVar(&flagInteractive, "i", false, "interactive prompt/visual terminal output if set")
	flag.BoolVar(&flagGzipProcessing, "gz", false, "(experimental) use gzip during processing of peers to shift ram usage at the cost of slowed processing")
	flag.StringVar(&flagConfig, "f", "", "output (aka config) file to load, such as output.yml")
	flag.StringVar(&flagOutput, "o", "", "file name to save to, such as output.yml")

	flag.Parse()
}

func main() {
	parseFlags()

	conf := gen.Configuration{
		GenerationParams: gen.GenerationForm{
			CIDR:                "10.0.0.0/16",
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

	var spinner *pterm.SpinnerPrinter

	var err error

	if flagConfig != "" {
		exists := true

		if flagInteractive {
			spinner, _ = pterm.DefaultSpinner.Start(fmt.Sprintf("loading from existing config file %v", flagConfig))
		}

		existing, err := os.ReadFile(flagConfig)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				exists = false
			} else {
				log.Fatalf("failed to read from %v: %v", flagConfig, err.Error())
			}
		}

		if exists {
			err = yaml.Unmarshal(existing, &conf)
			if err != nil {
				log.Fatalf("failed to unmarshal existing config: %v", err.Error())
			}

			if flagInteractive {
				spinner.Stop()
				spinner.Success()
			}
		} else {
			if flagInteractive {
				msg := fmt.Sprintf("will create a new config at %v (does not currently exist)", flagConfig)
				spinner.Info(msg)
				spinner.Stop()
			}
		}
	}

	conf.UseGzipDuringProcessing = flagGzipProcessing

	err = conf.Generate(flagInteractive)
	if err != nil {
		log.Fatalf("failed to generate: %v", err.Error())
	}

	if flagInteractive {
		spinner, _ = pterm.DefaultSpinner.Start("marshaling config")
	}

	b, err := yaml.Marshal(conf)
	if err != nil {
		log.Fatalf("failed to marshal conf: %v", err.Error())
	}

	if flagInteractive {
		spinner.Success()
		spinner.Stop()

		spinner, _ = pterm.DefaultSpinner.Start(fmt.Sprintf("writing %v bytes to %v", len(b), flagOutput))
	}

	err = os.WriteFile(flagOutput, b, 0o644)
	if err != nil {
		log.Fatalf("failed to write output to %v: %v", flagOutput, err.Error())
	}

	if flagInteractive {
		spinner.Success()
		spinner.Stop()
	}
}
