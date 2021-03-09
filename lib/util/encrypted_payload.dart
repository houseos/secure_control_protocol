/*
secure_control_protocol
EncryptedPayload Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class EncryptedPayload {
  String base64DataWithMac;
  String base64Data;
  int dataLength;
  String base64Mac;
  String base64Nonce;

  EncryptedPayload(
      {this.base64Data,
      this.dataLength,
      this.base64Mac,
      this.base64DataWithMac,
      this.base64Nonce});
}
