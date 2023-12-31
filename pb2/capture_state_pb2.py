# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: capture_state.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='capture_state.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x13\x63\x61pture_state.proto\x12\x11insta360.messages*\x85\x05\n\x12\x43\x61meraCaptureState\x12\x0f\n\x0bNOT_CAPTURE\x10\x00\x12\x12\n\x0eNORMAL_CAPTURE\x10\x01\x12\x15\n\x11TIMELAPSE_CAPTURE\x10\x02\x12\x1d\n\x19INTERVAL_SHOOTING_CAPTURE\x10\x03\x12\x13\n\x0fSINGLE_SHOOTING\x10\x04\x12\x10\n\x0cHDR_SHOOTING\x10\x05\x12\x17\n\x13SELF_TIMER_SHOOTING\x10\x06\x12\x17\n\x13\x42ULLET_TIME_CAPTURE\x10\x07\x12\x16\n\x12SETTINGS_NEW_VALUE\x10\x08\x12\x0f\n\x0bHDR_CAPTURE\x10\t\x12\x12\n\x0e\x42URST_SHOOTING\x10\n\x12\x1d\n\x19STATIC_TIMELAPSE_SHOOTING\x10\x0b\x12\x1a\n\x16INTERVAL_VIDEO_CAPTURE\x10\x0c\x12\x15\n\x11TIMESHIFT_CAPTURE\x10\r\x12\x16\n\x12\x41\x45\x42_NIGHT_SHOOTING\x10\x0e\x12\x1e\n\x1aSINGLE_POWER_PANO_SHOOTING\x10\x0f\x12\x1b\n\x17HDR_POWER_PANO_SHOOTING\x10\x10\x12\x18\n\x14SUPER_NORMAL_CAPTURE\x10\x11\x12\x1a\n\x16LOOP_RECORDING_CAPTURE\x10\x12\x12\x16\n\x12STARLAPSE_SHOOTING\x10\x13\x12\x19\n\x15\x46PV_RECORDING_CAPTURE\x10\x14\x12\x1b\n\x17MOVIE_RECORDING_CAPTURE\x10\x15\x12\x17\n\x13SLOW_MOTION_CAPTURE\x10\x16\x12\x1c\n\x18SELFIE_RECORDING_CAPTURE\x10\x17\x12\x1a\n\x16PURE_RECORDING_CAPTURE\x10\x18\x42\x08\xa2\x02\x05INSPBb\x06proto3'
)

_CAMERACAPTURESTATE = _descriptor.EnumDescriptor(
  name='CameraCaptureState',
  full_name='insta360.messages.CameraCaptureState',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NOT_CAPTURE', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NORMAL_CAPTURE', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TIMELAPSE_CAPTURE', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='INTERVAL_SHOOTING_CAPTURE', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SINGLE_SHOOTING', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='HDR_SHOOTING', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SELF_TIMER_SHOOTING', index=6, number=6,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BULLET_TIME_CAPTURE', index=7, number=7,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SETTINGS_NEW_VALUE', index=8, number=8,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='HDR_CAPTURE', index=9, number=9,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BURST_SHOOTING', index=10, number=10,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STATIC_TIMELAPSE_SHOOTING', index=11, number=11,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='INTERVAL_VIDEO_CAPTURE', index=12, number=12,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TIMESHIFT_CAPTURE', index=13, number=13,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='AEB_NIGHT_SHOOTING', index=14, number=14,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SINGLE_POWER_PANO_SHOOTING', index=15, number=15,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='HDR_POWER_PANO_SHOOTING', index=16, number=16,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SUPER_NORMAL_CAPTURE', index=17, number=17,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LOOP_RECORDING_CAPTURE', index=18, number=18,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STARLAPSE_SHOOTING', index=19, number=19,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='FPV_RECORDING_CAPTURE', index=20, number=20,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MOVIE_RECORDING_CAPTURE', index=21, number=21,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SLOW_MOTION_CAPTURE', index=22, number=22,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SELFIE_RECORDING_CAPTURE', index=23, number=23,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PURE_RECORDING_CAPTURE', index=24, number=24,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=43,
  serialized_end=688,
)
_sym_db.RegisterEnumDescriptor(_CAMERACAPTURESTATE)

CameraCaptureState = enum_type_wrapper.EnumTypeWrapper(_CAMERACAPTURESTATE)
NOT_CAPTURE = 0
NORMAL_CAPTURE = 1
TIMELAPSE_CAPTURE = 2
INTERVAL_SHOOTING_CAPTURE = 3
SINGLE_SHOOTING = 4
HDR_SHOOTING = 5
SELF_TIMER_SHOOTING = 6
BULLET_TIME_CAPTURE = 7
SETTINGS_NEW_VALUE = 8
HDR_CAPTURE = 9
BURST_SHOOTING = 10
STATIC_TIMELAPSE_SHOOTING = 11
INTERVAL_VIDEO_CAPTURE = 12
TIMESHIFT_CAPTURE = 13
AEB_NIGHT_SHOOTING = 14
SINGLE_POWER_PANO_SHOOTING = 15
HDR_POWER_PANO_SHOOTING = 16
SUPER_NORMAL_CAPTURE = 17
LOOP_RECORDING_CAPTURE = 18
STARLAPSE_SHOOTING = 19
FPV_RECORDING_CAPTURE = 20
MOVIE_RECORDING_CAPTURE = 21
SLOW_MOTION_CAPTURE = 22
SELFIE_RECORDING_CAPTURE = 23
PURE_RECORDING_CAPTURE = 24


DESCRIPTOR.enum_types_by_name['CameraCaptureState'] = _CAMERACAPTURESTATE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
