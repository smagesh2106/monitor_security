install:
	rm -f ~/go/bin/monitor_security
	go install -v
.PHONY: install

init:
	rm -f go.mod go.sum
	go mod init
	go mod tidy	
.PHONY: init

