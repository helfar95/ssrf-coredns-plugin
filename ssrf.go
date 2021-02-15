// Package ssrf is a CoreDNS plugin
package ssrf

import (
	"context"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("ssrf")
var prohibtedIPs = []string{"169.254.169.254"}

// Ssrf plugin
type Ssrf struct {
	Next plugin.Handler
}

// Name implements the Handler interface.
func (s Ssrf) Name() string { return "ssrf" }

// ServeDNS implements the plugin.Handler interface.
func (s Ssrf) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()

	answers := []dns.RR{}
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET}

	answers = append(answers, rr)

	for i := 0; i < len(answers); i++ {
		answer := answers[i]
		if inList(answer.String(), prohibtedIPs) {
			return dns.RcodeNameError, nil
		}
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers
	w.WriteMsg(m)

	return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
}
