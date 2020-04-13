package main

import (
	"encoding/csv"
	"fmt"
	"github.com/openshift/oauth-proxy/providers"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"
)

type UserMap struct {
	usersFile string
	m         unsafe.Pointer
}

func NewUserMap(usersFile string, done <-chan bool, onUpdate func()) *UserMap {
	um := &UserMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m))
	if usersFile != "" {
		log.Printf("using authenticated emails file %s", usersFile)
		WatchForUpdates(usersFile, done, func() {
			um.LoadAuthenticatedEmailsFile()
			onUpdate()
		})
		um.LoadAuthenticatedEmailsFile()
	}
	return um
}

func (um *UserMap) IsValid(email string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[email]
	return
}

func (um *UserMap) LoadAuthenticatedEmailsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		log.Fatalf("failed opening authenticated-emails-file=%q, %s", um.usersFile, err)
	}
	defer r.Close()
	csv_reader := csv.NewReader(r)
	csv_reader.Comma = ','
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true
	records, err := csv_reader.ReadAll()
	if err != nil {
		log.Printf("error reading authenticated-emails-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		address := strings.ToLower(strings.TrimSpace(r[0]))
		updated[address] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated))
}

func newValidatorImpl(domains []string, usersFile string,
	done <-chan bool, onUpdate func()) func(providers.SessionState) bool {
	validUsers := NewUserMap(usersFile, done, onUpdate)

	var allowAll bool
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
			continue
		}
		domains[i] = fmt.Sprintf("@%s", strings.ToLower(domain))
	}

	validator := func(s providers.SessionState) (valid bool) {
		if s.Email == "" {
			return
		}
		email := strings.ToLower(s.Email)
		for _, domain := range domains {
			valid = valid || strings.HasSuffix(email, domain)
		}
		if !valid {
			valid = validUsers.IsValid(email)
		}
		if allowAll {
			valid = true
		}
		return valid
	}
	return validator
}

func NewValidator(domains []string, usersFile string) func(providers.SessionState) bool {
	return newValidatorImpl(domains, usersFile, nil, func() {})
}
