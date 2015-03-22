package main

import "os"
import "net"
import "flag"
import "regexp"
import "bufio"
import "code.google.com/p/go-sqlite/go1/sqlite3"
import "fmt"

type ScanResult struct {
	domain_name string
	spf_string string
	dmarc_string string
}

func LookupSPF(domain string) (string, error) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return "", err
	}

	for _, record := range txtRecords {
		match, _ := regexp.MatchString("^v=spf1.*", record)
		if match == true {
			return record, nil
		}
	}

	return "", nil
}

func LookupDMARC(domain string) (string, error) {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return "", err
	}

	for _, record := range txtRecords {
		match, _ := regexp.MatchString("^v=DMARC1.*", record)
		if match == true {
			return record, nil
		}
	}

	return "", nil
}

func ingestDomains(inFileName string, ingestQueue chan<- string, numChan chan<- int) {
	file, err := os.Open(inFileName)
	numDomains := 0
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer file.Close()

	reader := bufio.NewReader(file)
	scanner := bufio.NewScanner(reader)

	fmt.Println("File Reader: Initialized")

	for scanner.Scan() {
		ingestQueue <- scanner.Text()
		numDomains += 1
		fmt.Println("File Reader: Added " + scanner.Text())
	}
	close(ingestQueue)
	numChan <- numDomains
}

// Does the heavy lifting
func ingestWorker(id int, ingestQueue <-chan string, resultsQueue chan<- ScanResult, 
				  scanSpf bool, scanDmarc bool) {
	fmt.Println("Ingest Worker ", id, " initialized")
	for domain := range ingestQueue {
		fmt.Println("Ingest Worker ", id, "processing ", domain)
		result := ScanResult{domain_name: domain}
		result.spf_string, _ = LookupSPF(domain)
		result.dmarc_string, _ = LookupDMARC(domain)

		resultsQueue <- result
	}
}

func resultsWorker(resultsQueue <-chan ScanResult, dbName string, numDomains <-chan int) {
	c, _ := sqlite3.Open(dbName)

	fmt.Println("Results Worker initialized")
	num, _ := <- numDomains
	var result ScanResult

	for i := 0; i < num; i++ {
		result, _ = <- resultsQueue 
		fmt.Println("Results worker processing ", result.domain_name)
		all_r, _ := regexp.Compile(".all")
		all_s := all_r.FindString(result.spf_string)

		p_r, _ := regexp.Compile("p=.*?;")
		p_s := p_r.FindString(result.dmarc_string)

		args := sqlite3.NamedArgs{"$domain": result.domain_name, 
								  "$spf_string": result.spf_string,
								  "$dmarc_string": result.dmarc_string,
								  "$spf_all": all_s,
								  "$dmarc_p": p_s,
								}
		err := c.Exec("INSERT INTO results(domain_name, spf_string, dmarc_string, spf_all, dmarc_p) VALUES($domain, $spf_string, $dmarc_string, $spf_all, $dmarc_p);", args)
		if err != nil {
			fmt.Println(err)
		}
		
	}
}

func main() {

	/* Set up command line arguments */
	spfScan := flag.Bool("spf", false, "Scan targets for SPF")
	dmarcScan := flag.Bool("dmarc", false, "Scan targets for DMARC")
	scanAll := flag.Bool("all", true, "Scan targets for both SPF and DMARC")

	inFileName := flag.String("infile", "", "File with target lists (one domain per line)")
	targetName := flag.String("target", "", "Domain to target")
	dbName := flag.String("db", "spfmap.db", "Name of the SQLite3 database to target")
	ingestWorkerNumber := flag.Int("workers", 5, "Number of workers to process the data")


	flag.Parse()


	// Set up ingest and results queues

	ingestQueue := make(chan string, 100)
	resultsQueue := make(chan ScanResult, 100)
	numDomains := make(chan int)

	fmt.Println("Made Channels")

	// Logic to ensure we scan the right stuff
	runSpfScan := false
	runDmarcScan := false
	if *spfScan == true || *scanAll == true {
		runSpfScan = true
	}
	if *dmarcScan == true || *scanAll == true {
		runDmarcScan = true
	}

	fmt.Println("Scanning DMARC: ", runDmarcScan)
	fmt.Println("Scanning SPF: ", runSpfScan)

	// Spin out a number of ingest workers based on user input
	for w := 1; w <= *ingestWorkerNumber; w++ {
		go ingestWorker(w, ingestQueue, resultsQueue, runSpfScan, runDmarcScan)
	}

	if *inFileName != "" {
		go ingestDomains(*inFileName, ingestQueue, numDomains)
	} else if *targetName != "" {
		ingestQueue <- *targetName
		close(ingestQueue)
	} else {
		fmt.Println("[-] ERROR: You need to provide some target")
		os.Exit(1)
	}

	resultsWorker(resultsQueue, *dbName, numDomains)

}