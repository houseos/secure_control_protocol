# scp-client Makefile
# SPDX-License-Identifier: MIT
# Copyright (C) 2020 Benjamin Schilling

.PHONY: all build install clean

all: clean build

build:
		dart pub get
		dart compile exe bin/scp_client.dart

install:
		mkdir -p $(DESTDIR)/usr/bin/
		cp bin/scp_client.exe $(DESTDIR)/usr/bin/scp-client

clean:
		rm -f -r bin/scp-client
