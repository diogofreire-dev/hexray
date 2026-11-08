# Usage:
#   make                 builds build/hexray
#   make debug           builds build/debug/hexray with ASan and UBSan
#   make test            builds both and runs every test script on them
#   make run ARGS="dump README.md"     builds and runs the debug version
#   make leaks ARGS="dump README.md"   checks the normal build for memory leaks
#   make clean           removes build/
CC      = clang
CFLAGS  = -std=c17 -Wall -Wextra -g
# -MMD -MP write a .d file next to each .o listing the headers that .c includes,
# so changing a header rebuilds exactly the files that use it
DEPFLAGS = -MMD -MP
SANITIZE = -fsanitize=address,undefined
# The maths library (log2). macOS always links it, but Linux needs to be told.
LDLIBS  = -lm
BUILD   = build

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c,$(BUILD)/obj/%.o,$(SRCS))
DEBUG_OBJS = $(patsubst src/%.c,$(BUILD)/debug/obj/%.o,$(SRCS))

TARGET = $(BUILD)/hexray
DEBUG_TARGET = $(BUILD)/debug/hexray

# No built-in rules: we say exactly how everything is built
MAKEFLAGS += -r
.SUFFIXES:

.PHONY: all debug test run leaks clean help
all: $(TARGET)

debug: $(DEBUG_TARGET)

help:
	@echo "Build:              make            (output in build/hexray)"
	@echo "Build with ASan:    make debug      (output in build/debug/hexray)"
	@echo "Run the tests:      make test"
	@echo "Run with arguments: make run ARGS=\"dump README.md\""
	@echo "Check for leaks:    make leaks ARGS=\"dump README.md\""
	@echo "Remove binaries:    make clean"

# Link: join every .o into one program
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(DEBUG_TARGET): $(DEBUG_OBJS)
	$(CC) $(CFLAGS) $(SANITIZE) $^ -o $@ $(LDLIBS)

# Compile: one .c into one .o. $< is the .c file, $@ is the .o being built
$(BUILD)/obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/debug/obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(SANITIZE) $(DEPFLAGS) -c $< -o $@

# The sanitized build catches memory bugs; the normal one is what actually ships
test: $(TARGET) $(DEBUG_TARGET)
	@for script in tests/test_*.sh; do \
		$$script $(DEBUG_TARGET) && $$script $(TARGET) || exit 1; \
	done

# The leading - keeps make going if the program exits with an error code
run: $(DEBUG_TARGET)
	-@./$< $(ARGS)

# Uses the normal build: AddressSanitizer cannot find leaks on macOS, and Apple's
# leaks tool does not work on a program built with it
leaks: $(TARGET)
	-@MallocStackLogging=1 leaks --atExit -- ./$< $(ARGS)

clean:
	rm -rf $(BUILD)

# The leading - means: on the first build these files do not exist yet, and that is fine
-include $(OBJS:.o=.d) $(DEBUG_OBJS:.o=.d)
