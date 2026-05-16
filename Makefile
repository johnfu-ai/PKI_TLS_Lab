.PHONY: up enroll tls12 tls13 analyze all clean down test build

build:
	./run-lab.sh build

up:
	./run-lab.sh up

enroll:
	./run-lab.sh enroll

tls12:
	./run-lab.sh tls12

tls13:
	./run-lab.sh tls13

analyze:
	./run-lab.sh analyze

all:
	./run-lab.sh all

clean:
	./scripts/clean.sh

down:
	docker compose down -v --remove-orphans 2>/dev/null || true

test:
	./run-lab.sh test
