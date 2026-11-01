package kone

import (
	"context"

	"github.com/miekg/dns"
)

// refreshResolution updates real DNS data without reallocating the Fake-IP.
// Callers own their record snapshot; established flows keep their chosen target.
func (d *Dns) refreshResolution(ctx context.Context, table *DnsTable, record *DomainRecord, request *dns.Msg) error {
	message, err := d.resolve(ctx, request)
	if err != nil {
		return err
	}
	record.SetRealIP(message)
	table.SetRealIP(record.Hostname, message)
	return nil
}
