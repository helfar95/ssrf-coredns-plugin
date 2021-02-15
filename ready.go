package ssrf

// Ready implements the ready.Readiness interface, once this flips to true CoreDNS
func (e Ssrf) Ready() bool { return true }
