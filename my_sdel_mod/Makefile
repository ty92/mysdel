obj-m:=del-mod3.o
all:
	make -C /usr/src/kernels/3.10.0-327.18.2.el7.x86_64/ M=$(shell pwd) modules
clean:
	make -C /usr/src/kernels/3.10.0-327.18.2.el7.x86_64/ M=$(shell pwd) clean
