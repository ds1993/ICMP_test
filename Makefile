all:
	gcc -o ping ping.c
	sudo chown root:root ping
	sudo chmod u+s ping

clean:
	sudo rm -f ping *~
