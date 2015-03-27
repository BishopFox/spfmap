package main

import "os"
import "net"
import "flag"
import "regexp"
import "bufio"
import "strconv"
import "github.com/mxk/go-sqlite/sqlite3"
import "sync"
import tm "github.com/buger/goterm"
import "github.com/alexcesaro/log/stdlog"
import "github.com/alexcesaro/log"

var logger log.Logger

type ScanResult struct {
	domain_name string
	spf_string string
	dmarc_string string
}

func createReport(dbName string) {
	c, _ := sqlite3.Open(dbName)

	q_numRecords := "SELECT count(*) FROM results;"
	q_numSpfRecords := "SELECT count(domain_name) FROM results WHERE spf_string NOT LIKE \"\""
	q_numDmarcRecords := "SELECT count(domain_name) FROM results WHERE dmarc_string NOT LIKE \"\""
	q_numSpfAll := "SELECT count(domain_name) FROM results WHERE (spf_all LIKE \"%all\")"
	q_numSpfMinusAll := "SELECT count(domain_name) FROM results WHERE (spf_all LIKE \"-all\")"
	q_numDmarcRejectQuarantine := "SELECT count(domain_name) FROM results WHERE (dmarc_p LIKE \"p=reject;\" OR dmarc_p LIKE \"p=quarantine;\")"
	q_numNotSpoofable := "SELECT count(domain_name) FROM results WHERE spf_all NOT LIKE \"\" AND (dmarc_p LIKE \"p=reject;\" OR dmarc_p LIKE \"p=quarantine;\")"

	s1, _ := c.Query(q_numRecords)
	var numRecords int64
	s1.Scan(&numRecords)
	s2, _ := c.Query(q_numSpfRecords)
	var numSpfRecords int64
	s2.Scan(&numSpfRecords)
	s3, _ := c.Query(q_numDmarcRecords)
	var numDmarcRecords int64
	s3.Scan(&numDmarcRecords)
	s4, _ := c.Query(q_numSpfAll)
	var numSpfAll int64
	s4.Scan(&numSpfAll)
	s5, _ := c.Query(q_numSpfMinusAll)
	var numSpfMinusAll int64
	s5.Scan(&numSpfMinusAll)
	s6, _ := c.Query(q_numDmarcRejectQuarantine)
	var numDmarcRejectQuarantine int64
	s6.Scan(&numDmarcRejectQuarantine)
	s7, _ := c.Query(q_numNotSpoofable)
	var numNotSpoofable int64
	s7.Scan(&numNotSpoofable)

	pctSpf := (float64(numSpfRecords)/float64(numRecords))*100
	pctDmarc := (float64(numDmarcRecords)/float64(numRecords))*100
	pctSpfAll := (float64(numSpfAll)/float64(numRecords))*100
	pctSpfMinusAll := (float64(numSpfMinusAll)/float64(numRecords))*100
	pctDmarcRejectQuarantine := (float64(numDmarcRejectQuarantine)/float64(numRecords))*100
	pctNotSpoofable := (float64(numNotSpoofable)/float64(numRecords))*100

	tm.Clear()

	tm.MoveCursor(1, 1)
	tm.Println(tm.Bold("SPF and DMARC Report"))
	tm.Println("====================")
	tm.Println("Number of records total:", numRecords)
	tm.Println("")
	tm.Println("Domains with SPF records:", numSpfRecords, "(", pctSpf, "%)")
	tm.Println("Domains with DMARC records:", numDmarcRecords, "(", pctDmarc, "%)")
	tm.Println("")
	tm.Println(tm.Bold("SPF Statistics"))
	tm.Println("--------------")
	tm.Println("Domains with ~all or -all:", numSpfAll, "(", pctSpfAll, "%)")
	tm.Println("Domains with -all:", numSpfMinusAll, "(", pctSpfMinusAll, "%)")
	tm.Println("")
	tm.Println(tm.Bold("DMARC Statistics"))
	tm.Println("----------------")	
	tm.Println("Domains with Reject or Quarantine Policy:", numDmarcRejectQuarantine, "(", pctDmarcRejectQuarantine, "%)")
	tm.Println("")
	tm.Println("")
	tm.Println("---------------------------------------------------")
	tm.Println(tm.Bold("Domains with non-spoofable configuration:"), tm.Color(strconv.Itoa(int(numNotSpoofable)), tm.RED), "(", pctNotSpoofable, "%)")
	tm.Println("---------------------------------------------------")

	tm.Flush()
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

func ingestDomains(inFileName string, ingestQueue chan<- string) {
	file, err := os.Open(inFileName)
	if err != nil {
		logger.Debug(err)
		os.Exit(1)
	}

	defer file.Close()

	reader := bufio.NewReader(file)
	scanner := bufio.NewScanner(reader)

	logger.Debug("File Reader: Initialized")

	for scanner.Scan() {
		ingestQueue <- scanner.Text()
		logger.Debug("File Reader: Added " + scanner.Text())
	}
	close(ingestQueue)
}

// Does the heavy lifting
func ingestWorker(id int, ingestQueue <-chan string, resultsQueue chan<- ScanResult, wg *sync.WaitGroup,
				  scanSpf bool, scanDmarc bool) {
	logger.Debug("Ingest Worker", id, "initialized")
	for domain := range ingestQueue {
		logger.Debug("Ingest Worker", id, "processing ", domain)
		result := ScanResult{domain_name: domain}
		result.spf_string, _ = LookupSPF(domain)
		result.dmarc_string, _ = LookupDMARC(domain)

		resultsQueue <- result
	}
	logger.Debug("Ingest Worker", id, "finished")
	wg.Done()
}

func closeResultsQueue(wg *sync.WaitGroup, resultsQueue chan ScanResult, numWorkers int) {
	wg.Wait()
	logger.Debug("Closing results queue")
	close(resultsQueue)
}

func resultsWorker(resultsQueue <-chan ScanResult, dbName string) {
	c, _ := sqlite3.Open(dbName)

	logger.Debug("Results Worker initialized")

	for result := range resultsQueue {
		logger.Debug("Results worker processing", result.domain_name)
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
			logger.Debug(err)
		}
		
	}
}

func main() {

	/* Set up command line arguments */
	spfScan := flag.Bool("spf", false, "Scan targets for SPF")
	dmarcScan := flag.Bool("dmarc", false, "Scan targets for DMARC")
	scanAll := flag.Bool("all", true, "Scan targets for both SPF and DMARC")

	genReport := flag.Bool("report", true, "Generate a report for the database")

	inFileName := flag.String("infile", "", "File with target lists (one domain per line)")
	targetName := flag.String("target", "", "Domain to target")
	dbName := flag.String("db", "spfmap.db", "Name of the SQLite3 database to target")
	ingestWorkerNumber := flag.Int("workers", 5, "Number of workers to process the data")


	flag.Parse()

	logger = stdlog.GetFromFlags()



	if *scanAll || *spfScan || *dmarcScan {

		// Set up ingest and results queues

		ingestQueue := make(chan string, 100)
		resultsQueue := make(chan ScanResult, 100)

		var wg sync.WaitGroup

		logger.Debug("Made Channels")

		// Logic to ensure we scan the right stuff
		runSpfScan := false
		runDmarcScan := false
		if *spfScan == true || *scanAll == true {
			runSpfScan = true
		}
		if *dmarcScan == true || *scanAll == true {
			runDmarcScan = true
		}

		logger.Debug("Scanning DMARC: ", runDmarcScan)
		logger.Debug("Scanning SPF: ", runSpfScan)

		// Spin out a number of ingest workers based on user input
		wg.Add(*ingestWorkerNumber)
		for w := 1; w <= *ingestWorkerNumber; w++ {
			go ingestWorker(w, ingestQueue, resultsQueue, &wg, runSpfScan, runDmarcScan)
		}

		if *inFileName != "" {
			go ingestDomains(*inFileName, ingestQueue)
		} else if *targetName != "" {
			ingestQueue <- *targetName
			close(ingestQueue)
		} else {
			os.Exit(1)
		}

		go closeResultsQueue(&wg, resultsQueue, *ingestWorkerNumber)

		resultsWorker(resultsQueue, *dbName)
	}

	if *genReport {
		createReport(*dbName)
	}

}