include Makefile.config

appName	= snifer
.PHONY = all clean

all:$(appName)

$(appName):snifer.o
	$(CC) $^ $(FLAG) $(LIBS) -o $@

%.o:%.c
	$(CC) -c $^

clean:
	rm $(appName) *.o
