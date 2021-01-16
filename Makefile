# scp-client Makefile
# SPDX-License-Identifier: MIT
# Copyright (C) 2020 Benjamin Schilling

.PHONY: all build clean

all: clean build

build:
		dart pub get
		dart compile exe bin/scp_client.dart
		mkdir $(DESTDIR)/usr/bin/scp-client
		cp bin/scp_client.exe $(DESTDIR)/usr/bin/scp-client

clean:
		rm -f -r bin/scp-client
