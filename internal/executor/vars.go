package executor

import "sync"

var (
	mu sync.Mutex
)

type GoogleDomainAvailabilityResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type GandiDomainAvailabilityResponse struct {
	Products []struct {
		Status string `json:"status"`
	} `json:"products"`
}
