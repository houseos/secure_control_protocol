# scp-client Makefile
# SPDX-License-Identifier: MIT
# Copyright (C) 2020 Benjamin Schilling

.PHONY: all build clean

all: clean build

build:
		dart compile exe bin/scp_client.dart

clean:
		rm -f -r bin/scp_client.dart
