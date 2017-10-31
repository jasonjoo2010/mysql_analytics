mysql_analytics: main.o
	cc -o mysql_analytics main.o -lpcap -ltcmalloc

all: mysql_analytics

clean:
	rm -rf *.o mysql_analytics

.PHONY: all clean