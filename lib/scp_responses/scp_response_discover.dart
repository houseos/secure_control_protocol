/*
secure_control_protocol
ScpResponseDiscover Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';

class ScpResponseDiscover {
  static const String type = "discover-response";
  String deviceId;
  String deviceType;
  int currentPasswordNumber;
  String hmac;

  ScpResponseDiscover(
      {this.deviceId, this.deviceType, this.currentPasswordNumber, this.hmac});

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  factory ScpResponseDiscover.fromJson(var json, List<ScpDevice> devices) {
    if (json['type'] == type) {
      if (json['deviceId'] == null ||
          json['deviceId'] == '' ||
          json['deviceType'] == null ||
          json['deviceType'] == '' ||
          json['currentPasswordNumber'] == null ||
          json['currentPasswordNumber'] == '' ||
          json['hmac'] == null ||
          json['hmac'] == '') {
        return null;
      }

      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        currentPasswordNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      String password = null;
      if (devices != null) {
        password = devices
            .firstWhere(
                (element) => element.deviceId == discoverResponse.deviceId)
            .knownPassword;
      }

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${discoverResponse.deviceId}${discoverResponse.deviceType}${discoverResponse.currentPasswordNumber}',
          discoverResponse.hmac,
          password)) {
        return discoverResponse;
      }
    }
    return null;
  }
}
