# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: timelapse_status_update.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='timelapse_status_update.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1dtimelapse_status_update.proto\x12\x11insta360.messages\";\n!NotificationTimeLapseStatusUpdate\x12\x16\n\x0einterval_count\x18\x01 \x01(\rB\x08\xa2\x02\x05INSPBb\x06proto3'
)




_NOTIFICATIONTIMELAPSESTATUSUPDATE = _descriptor.Descriptor(
  name='NotificationTimeLapseStatusUpdate',
  full_name='insta360.messages.NotificationTimeLapseStatusUpdate',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='interval_count', full_name='insta360.messages.NotificationTimeLapseStatusUpdate.interval_count', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
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
  serialized_start=52,
  serialized_end=111,
)

DESCRIPTOR.message_types_by_name['NotificationTimeLapseStatusUpdate'] = _NOTIFICATIONTIMELAPSESTATUSUPDATE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificationTimeLapseStatusUpdate = _reflection.GeneratedProtocolMessageType('NotificationTimeLapseStatusUpdate', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATIONTIMELAPSESTATUSUPDATE,
  '__module__' : 'timelapse_status_update_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificationTimeLapseStatusUpdate)
  })
_sym_db.RegisterMessage(NotificationTimeLapseStatusUpdate)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
