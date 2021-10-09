package util

import (
	"time"

	mod "github.com/monitor_security/model"
)

func UpdateSubscription(s *mod.SubscriptionInfo) {
	s.IsValid = true

	t := time.Now().AddDate(0, s.ValidityMonths, 0)
	s.Expiry = t
	s.Expiry_HR = t.Format(time.RFC1123)
}
