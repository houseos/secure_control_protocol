import 'dart:convert';

import 'package:http/http.dart';
import 'package:secure_control_protocol/scp_crypto.dart';

class ScpResponseDiscover {
  static const String type = "discover-response";
  String deviceId;
  String deviceType;
  int currentPasswordNumber;
  String hmac;

  ScpResponseDiscover(
      {this.deviceId, this.deviceType, this.currentPasswordNumber, this.hmac});

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  factory ScpResponseDiscover.fromJson(var json) {
    if (json['type'] == type) {
      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        currentPasswordNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${discoverResponse.deviceId}${discoverResponse.deviceType}${discoverResponse.currentPasswordNumber}',
          discoverResponse.hmac)) {
        return discoverResponse;
      }
    }

    return null;
  }
}

class ScpResponseFetchNvcn{

  static const String type = "security-fetch-nvcn";
  String deviceId;
  String nvcn;
  String hmac;

  ScpResponseFetchNvcn({this.deviceId, this.nvcn, this.hmac});

  factory ScpResponseFetchNvcn.fromJson(var json){
    if (json['type'] == type) {
      ScpResponseFetchNvcn nvcnResponse = ScpResponseFetchNvcn(
        deviceId: json['deviceId'],
        nvcn: json['nvcn'],
        hmac: json['hmac'],
      );

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${nvcnResponse.deviceId}${nvcnResponse.nvcn}',
          nvcnResponse.hmac));{
        return nvcnResponse;
      }
    }
    return null;
  }
}


class ScpResponseSetPassword{

  static const String type = "security-pw-change";
  String deviceId;
  String currentPasswordNumber;
  String result;
  String hmac;

  ScpResponseSetPassword({this.deviceId, this.currentPasswordNumber, this.result, this.hmac});

  factory ScpResponseSetPassword.fromJson(var json){
    if (json['type'] == type) {
      ScpResponseSetPassword setPasswordResponse = ScpResponseSetPassword(
        deviceId: json['deviceId'],
        currentPasswordNumber: json['currentPasswordNumber'],
        result: json['result'],
        hmac: json['hmac'],
      );

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${setPasswordResponse.deviceId}${setPasswordResponse.currentPasswordNumber}${setPasswordResponse.result}',
          setPasswordResponse.hmac));{
        return setPasswordResponse;
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
  
  static ScpResponseFetchNvcn parseNvcnResponse(var response) {
    return ScpResponseFetchNvcn.fromJson(
        json.decode(utf8.decode(response.bodyBytes)));
  }
  static ScpResponseSetPassword parseSetPasswordResponse(var response) {
    return ScpResponseSetPassword.fromJson(
        json.decode(utf8.decode(response.bodyBytes)));
  }
}
