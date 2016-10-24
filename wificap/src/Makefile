objects = main.o pcap.o db.o

pcaptest : $(objects)
	gcc -o wificap $(objects) -L/usr/lib/i386-linux-gnu -lmysqlclient

main.o:pcap.h db.h
pcap.o:pcap.h
db.o:db.h

.PHONY : clean
clean:
	rm wificap $(objects)
