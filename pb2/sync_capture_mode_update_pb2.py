# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: sync_capture_mode_update.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='sync_capture_mode_update.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1esync_capture_mode_update.proto\x12\x11insta360.messages\"#\n!NotificationSyncCaptureModeUpdateB\x08\xa2\x02\x05INSPBb\x06proto3'
)




_NOTIFICATIONSYNCCAPTUREMODEUPDATE = _descriptor.Descriptor(
  name='NotificationSyncCaptureModeUpdate',
  full_name='insta360.messages.NotificationSyncCaptureModeUpdate',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=53,
  serialized_end=88,
)

DESCRIPTOR.message_types_by_name['NotificationSyncCaptureModeUpdate'] = _NOTIFICATIONSYNCCAPTUREMODEUPDATE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificationSyncCaptureModeUpdate = _reflection.GeneratedProtocolMessageType('NotificationSyncCaptureModeUpdate', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATIONSYNCCAPTUREMODEUPDATE,
  '__module__' : 'sync_capture_mode_update_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificationSyncCaptureModeUpdate)
  })
_sym_db.RegisterMessage(NotificationSyncCaptureModeUpdate)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
