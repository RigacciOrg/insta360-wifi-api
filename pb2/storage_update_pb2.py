# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: storage_update.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import storage_pb2 as storage__pb2

from storage_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='storage_update.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x14storage_update.proto\x12\x11insta360.messages\x1a\rstorage.proto\"x\n\x16NotificationCardUpdate\x12+\n\x05state\x18\x01 \x01(\x0e\x32\x1c.insta360.messages.CardState\x12\x31\n\x08location\x18\x02 \x01(\x0e\x32\x1f.insta360.messages.CardLocationB\x08\xa2\x02\x05INSPBP\x00\x62\x06proto3'
  ,
  dependencies=[storage__pb2.DESCRIPTOR,],
  public_dependencies=[storage__pb2.DESCRIPTOR,])




_NOTIFICATIONCARDUPDATE = _descriptor.Descriptor(
  name='NotificationCardUpdate',
  full_name='insta360.messages.NotificationCardUpdate',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='state', full_name='insta360.messages.NotificationCardUpdate.state', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='location', full_name='insta360.messages.NotificationCardUpdate.location', index=1,
      number=2, type=14, cpp_type=8, label=1,
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
  serialized_start=58,
  serialized_end=178,
)

_NOTIFICATIONCARDUPDATE.fields_by_name['state'].enum_type = storage__pb2._CARDSTATE
_NOTIFICATIONCARDUPDATE.fields_by_name['location'].enum_type = storage__pb2._CARDLOCATION
DESCRIPTOR.message_types_by_name['NotificationCardUpdate'] = _NOTIFICATIONCARDUPDATE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificationCardUpdate = _reflection.GeneratedProtocolMessageType('NotificationCardUpdate', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATIONCARDUPDATE,
  '__module__' : 'storage_update_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificationCardUpdate)
  })
_sym_db.RegisterMessage(NotificationCardUpdate)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)