/*
secure_control_protocol
InputValidation Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class InputValidation {
  static bool isNull(Object o){
    if(o == null) {
      return true;
    }
    return false;
  }

  static bool isEmpty(Object o){
    if (o == '') {
      return true;
    }
    return false;
  }
}