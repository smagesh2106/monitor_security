package util

import (
	"time"

	mod "github.com/monitor_security/model"
)

func UpdateSubscription(s *mod.SubscriptionInfo) {

	t := time.Now().AddDate(0, s.ValidityMonths, 0)
	//t := time.Now().Add(10 * time.Second) //for testing only.
	s.Expiry = t
	s.Expiry_HR = t.Format(time.RFC1123)
}
