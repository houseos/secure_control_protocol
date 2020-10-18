/*
secure_control_protocol
ScpResponseFetchNvcn Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class ScpResponseFetchNvcn {
  static const String type = "security-fetch-nvcn";
  String deviceId;
  String nvcn;

  ScpResponseFetchNvcn({this.deviceId, this.nvcn});

  factory ScpResponseFetchNvcn.fromJson(var json) {
    if (json['type'] == type) {
      if (json['deviceId'] == null ||
          json['deviceId'] == '' ||
          json['nvcn'] == null ||
          json['nvcn'] == '') {
        return null;
      }

      ScpResponseFetchNvcn nvcnResponse = ScpResponseFetchNvcn(
        deviceId: json['deviceId'],
        nvcn: json['nvcn'],
      );

      return nvcnResponse;
    }
    return null;
  }
}