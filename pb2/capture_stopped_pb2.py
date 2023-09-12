# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: capture_stopped.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import video_pb2 as video__pb2

from video_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='capture_stopped.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x15\x63\x61pture_stopped.proto\x12\x11insta360.messages\x1a\x0bvideo.proto\"\xa9\x03\n\x1aNotificationCaptureStopped\x12I\n\x08\x65rr_code\x18\x01 \x01(\x0e\x32\x37.insta360.messages.NotificationCaptureStopped.ErrorCode\x12\'\n\x05video\x18\x02 \x01(\x0b\x32\x18.insta360.messages.Video\"\x96\x02\n\tErrorCode\x12\x13\n\x0fOVER_TIME_LIMIT\x10\x00\x12\x10\n\x0cSTORAGE_FULL\x10\x01\x12\x13\n\x0fOTHER_SITUATION\x10\x02\x12\x1a\n\x16OVER_FILE_NUMBER_LIMIT\x10\x03\x12\x12\n\x0eLOW_CARD_SPEED\x10\x04\x12\x16\n\x12MUXER_STREAM_ERROR\x10\x05\x12\x0f\n\x0b\x44ROP_FRAMES\x10\x06\x12\x0f\n\x0bLOW_BATTERY\x10\x07\x12\x10\n\x0cSTORAGEFRGMT\x10\x08\x12\r\n\tHIGH_TEMP\x10\t\x12\x13\n\x0fLOW_POWER_START\x10\n\x12\x18\n\x14STORAGE_RUNOUT_START\x10\x0b\x12\x13\n\x0fHIGH_TEMP_START\x10\x0c\x42\x08\xa2\x02\x05INSPBP\x00\x62\x06proto3'
  ,
  dependencies=[video__pb2.DESCRIPTOR,],
  public_dependencies=[video__pb2.DESCRIPTOR,])



_NOTIFICATIONCAPTURESTOPPED_ERRORCODE = _descriptor.EnumDescriptor(
  name='ErrorCode',
  full_name='insta360.messages.NotificationCaptureStopped.ErrorCode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='OVER_TIME_LIMIT', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STORAGE_FULL', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='OTHER_SITUATION', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='OVER_FILE_NUMBER_LIMIT', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LOW_CARD_SPEED', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MUXER_STREAM_ERROR', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='DROP_FRAMES', index=6, number=6,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LOW_BATTERY', index=7, number=7,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STORAGEFRGMT', index=8, number=8,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='HIGH_TEMP', index=9, number=9,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LOW_POWER_START', index=10, number=10,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STORAGE_RUNOUT_START', index=11, number=11,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='HIGH_TEMP_START', index=12, number=12,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=205,
  serialized_end=483,
)
_sym_db.RegisterEnumDescriptor(_NOTIFICATIONCAPTURESTOPPED_ERRORCODE)


_NOTIFICATIONCAPTURESTOPPED = _descriptor.Descriptor(
  name='NotificationCaptureStopped',
  full_name='insta360.messages.NotificationCaptureStopped',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='err_code', full_name='insta360.messages.NotificationCaptureStopped.err_code', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='video', full_name='insta360.messages.NotificationCaptureStopped.video', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _NOTIFICATIONCAPTURESTOPPED_ERRORCODE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=58,
  serialized_end=483,
)

_NOTIFICATIONCAPTURESTOPPED.fields_by_name['err_code'].enum_type = _NOTIFICATIONCAPTURESTOPPED_ERRORCODE
_NOTIFICATIONCAPTURESTOPPED.fields_by_name['video'].message_type = video__pb2._VIDEO
_NOTIFICATIONCAPTURESTOPPED_ERRORCODE.containing_type = _NOTIFICATIONCAPTURESTOPPED
DESCRIPTOR.message_types_by_name['NotificationCaptureStopped'] = _NOTIFICATIONCAPTURESTOPPED
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificationCaptureStopped = _reflection.GeneratedProtocolMessageType('NotificationCaptureStopped', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATIONCAPTURESTOPPED,
  '__module__' : 'capture_stopped_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificationCaptureStopped)
  })
_sym_db.RegisterMessage(NotificationCaptureStopped)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)