package executor

import "sync"

var (
	mu sync.Mutex
)

type DomainAvailabilityResponse struct {
	Products []struct {
		Status string `json:"status"`
	} `json:"products"`
}
