/*
secure_control_protocol
ScpResponseFetchNvcn Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

import 'package:secure_control_protocol/scp_responses/ivalidatable.dart';

class ScpResponseFetchNvcn implements IValidatable {
  static const String type = "security-fetch-nvcn";
  String _deviceId = '';
  String _nvcn = '';

  ScpResponseFetchNvcn({String deviceId = '', String nvcn = ''}){
    _deviceId =deviceId;
    _nvcn =nvcn;
  }

  factory ScpResponseFetchNvcn.fromJson(var json) {
    if (json['type'] == type) {
      if (json['deviceId'] == null ||
          json['deviceId'] == '' ||
          json['nvcn'] == null ||
          json['nvcn'] == '') {
        return ScpResponseFetchNvcn();
      }

      ScpResponseFetchNvcn nvcnResponse = ScpResponseFetchNvcn(
        deviceId: json['deviceId'],
        nvcn: json['nvcn'],
      );

      return nvcnResponse;
    }
    return ScpResponseFetchNvcn();
  }

  String getNVCN() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _nvcn;
    }
  }

  String getDeviceId() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _deviceId;
    }
  }

  bool isValid() {
    if (_deviceId != '' && _nvcn != '') {
      return true;
    }
    return false;
  }
}
