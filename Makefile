CCX        := gcc
FLAGS      := -Wall
OUT_DIR    := .build

.PHONY: all
all:
	mkdir -p $(OUT_DIR)
	$(CCX) $(FLAGS) -o $(OUT_DIR)/build src/uuhttp.c
	./$(OUT_DIR)/build