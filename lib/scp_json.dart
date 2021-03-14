/*
secure_control_protocol
ScpJson Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// SCP Util
import 'package:secure_control_protocol/util/encrypted_payload.dart';

class ScpJson {
  String key;
  EncryptedPayload encryptedPayload;

  ScpJson({this.key = '', this.encryptedPayload = const EncryptedPayload()});

  Map<String, dynamic> toJson() => {
        'key': key,
        'payload': encryptedPayload.base64Data,
        'payloadLength': encryptedPayload.dataLength,
        'mac': encryptedPayload.base64Mac,
      };
}
