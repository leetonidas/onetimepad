OBJS = onetimepad.o
LDFLAGS = -Wl,-z,relro,-z,now
CFLAGS = -fstack-protector -Wall -Werror -pedantic

all: vuln

vuln: $(OBJS)
	gcc $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJS) vuln

.PHONY: all clean