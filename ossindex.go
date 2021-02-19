package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type ComponentReportRequest struct 
{
	Coordinates []string `json:"coordinates"`
}

type ComponentReport struct 
{
	Coordinates     string          `json:"coordinates"`
	Description     string          `json:"description"`
	Reference       string          `json:"reference"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct
{
	Id 					  string   `json:"id"`
	DisplayName   string   `json:"displayName"`
	Title				  string   `json:"title"`
	Description   string   `json:"description"`
	CVSSScore	    float32  `json:"cvssScore"`
	CVSSVector    string   `json:"cvssVector"`
	CWE           string   `json:"cwe"`
	CVE						string   `json:"cve"`
	Reference     string   `json:"reference"`
	VersionRanges []string `json:"versionRanges"`
}

func CheckOssIndex(coordinates []string, username string, password string) *[]ComponentReport {
	var requestObject = ComponentReportRequest{ Coordinates:coordinates }
	var content, err = json.Marshal(requestObject)
	if err != nil{
		log.Fatal(err)
	}
	
	client := &http.Client{ Timeout: time.Second * 10 }
	req, err := http.NewRequest("POST", "https://ossindex.sonatype.org/api/v3/component-report", bytes.NewBuffer(content))
	req.Header.Set("Content-Type", "application/json")
	if len(username) > 0 && len(password) > 0 {
		req.SetBasicAuth(username, password)
	}

	response, err := client.Do(req)
	if err != nil{
			log.Fatal(err)
	}

	bodyText, err := ioutil.ReadAll(response.Body)
	var componentReports []ComponentReport
	err = json.Unmarshal(bodyText, &componentReports)
	if err != nil {
		fmt.Println("error:", err)
	}

	return &componentReports
}

func GetSeverityColour(cvssScore float32) string {
	// https://nvd.nist.gov/vuln-metrics/cvss
	switch {
	// None
	case cvssScore < 0.1:
		return "#fff"
	// Low
	case cvssScore < 3.9:
		return "#c4c4c4"
	// Medium
	case cvssScore < 6.9:
		return "#ffc65e"
	// High
	case cvssScore < 8.9:
		return "#bd002b"
	}

	// Critical
	return "#bd002b"
}

func GetSeverityClass(cvssScore float32) string {
	// https://nvd.nist.gov/vuln-metrics/cvss
	switch {
	case cvssScore < 0.1:
		return "None"
	case cvssScore < 3.9:
		return "Low"
	case cvssScore < 6.9:
		return "Medium"
	case cvssScore < 8.9:
		return "High"
	}

	return "Critical"
}