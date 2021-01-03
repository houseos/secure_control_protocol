# scp-client Makefile
# SPDX-License-Identifier: MIT
# Copyright (C) 2020 Benjamin Schilling

.PHONY: all build clean

all: clean build

build:
		dart pub get
		dart compile exe bin/scp_client.dart
		mv bin/scp_client.exe bin/scp_client

clean:
		rm -f -r bin/scp_client.exe
