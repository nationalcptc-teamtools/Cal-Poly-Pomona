package models

import (
	"encoding/xml"
)

type Nmaprun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            string   `xml:"start,attr"`
	Startstr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	Xmloutputversion string   `xml:"xmloutputversion,attr"`
	Scaninfo         struct {
		Type        string `xml:"type,attr"`
		Protocol    string `xml:"protocol,attr"`
		Numservices string `xml:"numservices,attr"`
		Services    string `xml:"services,attr"`
	} `xml:"scaninfo"`
	Verbose struct {
		Level string `xml:"level,attr"`
	} `xml:"verbose"`
	Debugging struct {
		Level string `xml:"level,attr"`
	} `xml:"debugging"`
	Host []struct {
		Starttime string `xml:"starttime,attr"`
		Endtime   string `xml:"endtime,attr"`
		Status    struct {
			State     string `xml:"state,attr"`
			Reason    string `xml:"reason,attr"`
			ReasonTtl string `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Address []struct {
			Addr     string `xml:"addr,attr"`
			Addrtype string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames struct {
			Hostname []struct {
				Name string `xml:"name,attr"`
				Type string `xml:"type,attr"`
			} `xml:"hostname"`
		}
		Ports     struct {
			Extraports struct {
				State        string `xml:"state,attr"`
				Count        string `xml:"count,attr"`
				Extrareasons struct {
					Reason string `xml:"reason,attr"`
					Count  string `xml:"count,attr"`
					Proto  string `xml:"proto,attr"`
					Ports  string `xml:"ports,attr"`
				} `xml:"extrareasons"`
			} `xml:"extraports"`
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				Portid   string `xml:"portid,attr"`
				State    struct {
					State     string `xml:"state,attr"`
					Reason    string `xml:"reason,attr"`
					ReasonTtl string `xml:"reason_ttl,attr"`
				} `xml:"state"`
				Service struct {
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Version   string `xml:"version,attr"`
					Extrainfo string `xml:"extrainfo,attr"`
					Method    string `xml:"method,attr"`
					Conf      string `xml:"conf,attr"`
					Tunnel    string `xml:"tunnel,attr"`
					Cpe       string `xml:"cpe"`
				} `xml:"service"`
				Script []struct {
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
					Elem   struct {
					Key  string `xml:"key,attr"`
					} `xml:"elem"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
		Times struct {
			Srtt   string `xml:"srtt,attr"`
			Rttvar string `xml:"rttvar,attr"`
			To     string `xml:"to,attr"`
		} `xml:"times"`
	} `xml:"host"`
	Runstats struct {
		Finished struct {
			Time    string `xml:"time,attr"`
			Timestr string `xml:"timestr,attr"`
			Summary string `xml:"summary,attr"`
			Elapsed string `xml:"elapsed,attr"`
			Exit    string `xml:"exit,attr"`
		} `xml:"finished"`
		Hosts struct {
			Up    string `xml:"up,attr"`
			Down  string `xml:"down,attr"`
			Total string `xml:"total,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}
