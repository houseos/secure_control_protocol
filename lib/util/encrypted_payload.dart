/*
secure_control_protocol
EncryptedPayload Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class EncryptedPayload {
  final String base64Data;
  final int dataLength;
  final String base64Mac;
  final String base64Nonce;
      
  const EncryptedPayload(
      {this.base64Data = '',
      this.dataLength = 0,
      this.base64Mac = '',
      this.base64Nonce = ''});
}
