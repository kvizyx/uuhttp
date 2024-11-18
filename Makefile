CCX        := gcc
FLAGS      := -Wall
OUT_DIR    := .build

.PHONY: all
all: build
	./$(OUT_DIR)/build

.PHONY: build
build:
	mkdir -p $(OUT_DIR)
	$(CCX) $(FLAGS) -o $(OUT_DIR)/build src/uuhttp.c