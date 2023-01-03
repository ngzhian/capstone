# Makefile for Cstool of Capstone Disassembly Engine

include ../functions.mk

.PHONY: clean all

LIBNAME = capstone

CFLAGS += -I../include -I.
LDFLAGS += -O3 -Wall -L.. -l$(LIBNAME)

TARGET = cstool
TARGET_JS = cstool.js
WASM_HTML = wasm.html
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
WASM_SOURCES = wasm.c
WASM_OBJECTS := $(WASM_SOURCES:.c=.o)

LIBCAPSTONE = libcapstone.a

IS_CYGWIN := $(shell $(CC) -dumpmachine 2>/dev/null | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
LIBCAPSTONE = capstone.lib
else
IS_MINGW := $(shell $(CC) --version 2>/dev/null | grep -i "\(mingw\|MSYS\)" | wc -l)
ifeq ($(IS_MINGW),1)
LIBCAPSTONE = capstone.lib
endif
endif

all: $(TARGET) $(TARGET_JS) $(WASM_HTML)

$(TARGET): ../$(LIBCAPSTONE) $(OBJECTS)
ifeq ($(V), 0)
	$(call log,LINK,$@)
	@${CC} $(OBJECTS) $(LDFLAGS) -o $@
else
	${CC} $(OBJECTS) $(LDFLAGS) -o $@
endif

$(TARGET_JS): ../$(LIBCAPSTONE) $(OBJECTS)
	${CC} $(OBJECTS) $(LDFLAGS) -o $@

$(WASM_HTML): ../$(LIBCAPSTONE) $(OBJECTS)
	${CC} -sEXPORTED_FUNCTIONS=_foo -sEXPORTED_RUNTIME_METHODS=ccall,cwrap $(WASM_OBJECTS) $(LDFLAGS) -o $@

clean:
	${RM} -rf *.o $(TARGET)
	${RM} -f *.d
	${RM} -f *.wasm *.js *.html

%.o: %.c
ifeq ($(V), 0)
	$(call log,CC,$@)
	@${CC} $(CFLAGS) -c $< -o $@
else
	${CC} $(CFLAGS) -c $< -o $@
endif
