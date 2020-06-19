package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/williballenthin/govt"
)

var apikey string
var file string
var ignoreEngines string

var verbose bool

func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VIRUSTOTAL_TOKEN"), "VirusTotal API key.")
	flag.StringVar(&file, "file", "", "File to scan.")
	flag.StringVar(&ignoreEngines, "ignore", "", "Comma-separated list of A/V engines to ignore")
	flag.BoolVar(&verbose, "verbose", false, "Be verbose")
}

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	if file == "" {
		fmt.Println("-file missing!")
		os.Exit(1)
	}
	apiurl := "https://www.virustotal.com/vtapi/v2/"
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Uploading", file, "...")
	r, err := c.ScanFile(file)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("File uploaded. Scan ID", r.ScanId)

	// wait for scan report to be completed
	var report *govt.FileReport
	for i := 1; i <= 30; i++ {
		fmt.Printf("Checking scan report %d/20\n", i)
		report, err = c.GetFileReport(r.ScanId)
		if err != nil {
			log.Println("GetFileReport error:", err)
			continue
		}

		if report.ResponseCode == 1 {
			fmt.Println("Report is done")
			break
		}
		if verbose {
			fmt.Printf("Partial report result: %+v\n", report)
		}

		time.Sleep(20 * time.Second)
	}

	if report == nil {
		fmt.Println("NO REPORT RECIEVED, GIVING UP")
		os.Exit(1)
	}

	positives := 0
	positiveFiltered := 0
	positiveResults := []result{}
	filteredResults := []result{}

	// count positive matches, filter out some AV engines
	for s, o := range report.Scans {
		for _, ignored := range strings.Split(ignoreEngines, ",") {
			if strings.ToLower(s) == strings.ToLower(ignored) {
				positiveFiltered++
				filteredResults = append(filteredResults, result{engine: s, result: o.Result})
			} else if o.Detected {
				positives++
				positiveResults = append(positiveResults, result{engine: s, result: o.Result})
			}
		}
	}

	if positives > 0 {
		fmt.Printf("Detected %d positives: %+v\n", positives, positiveResults)
	} else {
		fmt.Printf("No positives detected (%d filtered: %+v)\n", positiveFiltered, filteredResults)
	}

	os.Exit(positives)
}

type result struct {
	engine string
	result string
}
