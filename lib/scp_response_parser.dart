import 'dart:convert';

import 'package:http/http.dart';
import 'package:secure_control_protocol/scp_crypto.dart';

class ScpResponseDiscover {
  static const String type = "discover-response";
  String deviceId;
  String deviceType;
  int currentPassowrdNumber;
  String hmac;

  ScpResponseDiscover(
      {this.deviceId, this.deviceType, this.currentPassowrdNumber, this.hmac});

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  factory ScpResponseDiscover.fromJson(var json) {
    if (json['type'] == 'discover-response') {
      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        currentPassowrdNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${discoverResponse.deviceId}${discoverResponse.deviceType}${discoverResponse.currentPassowrdNumber}',
          discoverResponse.hmac)) {
        return discoverResponse;
      }
    }

    return null;
  }
}

class ScpResponseParser {
  static ScpResponseDiscover parseDiscoverResponse(var response) {
    return ScpResponseDiscover.fromJson(
        json.decode(utf8.decode(response.bodyBytes)));
  }
}
