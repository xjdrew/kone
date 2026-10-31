// author: xjdrew
// date: 2024-01-04

// Read system DNS config, support windows, macosx and linux.
// Code is mainly from golang standard net package.
// main changes:
// 1. make DnsConfig publicly accessible
// 2. remove unnecessary status
package dnsconfig
