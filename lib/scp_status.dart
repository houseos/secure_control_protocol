/*
secure_control_protocol
ScpStatus Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class ScpStatus {
  static const String RESULT_DONE = "done";
  static const String RESULT_SUCCESS = "success";
  static const String RESULT_ERROR = "error";
  static const String RESULT_ERROR_FAILED_FETCHING_NVCN = "failed fetching nvcn.";

  String status;

  ScpStatus({this.status = ScpStatus.RESULT_ERROR});

}

class ScpStatusMeasure extends ScpStatus{
  
  ScpStatusMeasure(String status, {this.value = ''}): super(status: status);

  String value;
}
