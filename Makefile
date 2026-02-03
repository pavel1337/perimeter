generate:
	go generate ./ent

run:
	@export $(shell cat .env | xargs); \
	go run main.go --targets targets.lst
