# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: current_capture_status.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import capture_state_pb2 as capture__state__pb2

from capture_state_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='current_capture_status.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1c\x63urrent_capture_status.proto\x12\x11insta360.messages\x1a\x13\x63\x61pture_state.proto\"w\n\rCaptureStatus\x12\x34\n\x05state\x18\x01 \x01(\x0e\x32%.insta360.messages.CameraCaptureState\x12\x14\n\x0c\x63\x61pture_time\x18\x02 \x01(\r\x12\x1a\n\x12keyTimePointDetail\x18\x03 \x01(\tB\x08\xa2\x02\x05INSPBP\x00\x62\x06proto3'
  ,
  dependencies=[capture__state__pb2.DESCRIPTOR,],
  public_dependencies=[capture__state__pb2.DESCRIPTOR,])




_CAPTURESTATUS = _descriptor.Descriptor(
  name='CaptureStatus',
  full_name='insta360.messages.CaptureStatus',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='state', full_name='insta360.messages.CaptureStatus.state', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='capture_time', full_name='insta360.messages.CaptureStatus.capture_time', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='keyTimePointDetail', full_name='insta360.messages.CaptureStatus.keyTimePointDetail', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=72,
  serialized_end=191,
)

_CAPTURESTATUS.fields_by_name['state'].enum_type = capture__state__pb2._CAMERACAPTURESTATE
DESCRIPTOR.message_types_by_name['CaptureStatus'] = _CAPTURESTATUS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CaptureStatus = _reflection.GeneratedProtocolMessageType('CaptureStatus', (_message.Message,), {
  'DESCRIPTOR' : _CAPTURESTATUS,
  '__module__' : 'current_capture_status_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.CaptureStatus)
  })
_sym_db.RegisterMessage(CaptureStatus)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
