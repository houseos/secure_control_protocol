# scp-client Makefile
# SPDX-License-Identifier: MIT
# Copyright (C) 2020 Benjamin Schilling

.PHONY: all build clean

all: clean build

build:
		dart pub get
		dart compile exe bin/scp-client.dart
		mv bin/scp-client.exe bin/scp-client

clean:
		rm -f -r bin/scp_client.exe
