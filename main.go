package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/williballenthin/govt"
)

var apikey string
var file string

func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VIRUSTOTAL_TOKEN"), "VirusTotal API key.")
	flag.StringVar(&file, "file", "", "File to scan.")
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

		time.Sleep(20 * time.Second)
		if report.ResponseCode == 1 {
			fmt.Println("Report is done")
			break
		}
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
		switch s {
		case "Cylance", "Jiangmin", "Ikarus", "MaxSecure":
			positiveFiltered++
			filteredResults = append(filteredResults, result{engine: s, result: o.Result})
			break

		default:
			if o.Detected {
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
