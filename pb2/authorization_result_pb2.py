# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: authorization_result.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import authorization_operation_type_pb2 as authorization__operation__type__pb2

from authorization_operation_type_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='authorization_result.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1a\x61uthorization_result.proto\x12\x11insta360.messages\x1a\"authorization_operation_type.proto\"\xaa\x02\n\x1fNotificationAuthorizationResult\x12\x64\n\x14\x61uthorization_result\x18\x01 \x01(\x0e\x32\x46.insta360.messages.NotificationAuthorizationResult.AuthorizationResult\x12S\n\x1c\x61uthorization_operation_type\x18\x02 \x01(\x0e\x32-.insta360.messages.AuthorizationOperationType\"L\n\x13\x41uthorizationResult\x12\x0b\n\x07SUCCESS\x10\x00\x12\n\n\x06REJECT\x10\x01\x12\x0b\n\x07TIMEOUT\x10\x02\x12\x0f\n\x0bSYSTEM_BUSY\x10\x03\x42\x08\xa2\x02\x05INSPBP\x00\x62\x06proto3'
  ,
  dependencies=[authorization__operation__type__pb2.DESCRIPTOR,],
  public_dependencies=[authorization__operation__type__pb2.DESCRIPTOR,])



_NOTIFICATIONAUTHORIZATIONRESULT_AUTHORIZATIONRESULT = _descriptor.EnumDescriptor(
  name='AuthorizationResult',
  full_name='insta360.messages.NotificationAuthorizationResult.AuthorizationResult',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SUCCESS', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='REJECT', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TIMEOUT', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SYSTEM_BUSY', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=308,
  serialized_end=384,
)
_sym_db.RegisterEnumDescriptor(_NOTIFICATIONAUTHORIZATIONRESULT_AUTHORIZATIONRESULT)


_NOTIFICATIONAUTHORIZATIONRESULT = _descriptor.Descriptor(
  name='NotificationAuthorizationResult',
  full_name='insta360.messages.NotificationAuthorizationResult',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='authorization_result', full_name='insta360.messages.NotificationAuthorizationResult.authorization_result', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='authorization_operation_type', full_name='insta360.messages.NotificationAuthorizationResult.authorization_operation_type', index=1,
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
    _NOTIFICATIONAUTHORIZATIONRESULT_AUTHORIZATIONRESULT,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=86,
  serialized_end=384,
)

_NOTIFICATIONAUTHORIZATIONRESULT.fields_by_name['authorization_result'].enum_type = _NOTIFICATIONAUTHORIZATIONRESULT_AUTHORIZATIONRESULT
_NOTIFICATIONAUTHORIZATIONRESULT.fields_by_name['authorization_operation_type'].enum_type = authorization__operation__type__pb2._AUTHORIZATIONOPERATIONTYPE
_NOTIFICATIONAUTHORIZATIONRESULT_AUTHORIZATIONRESULT.containing_type = _NOTIFICATIONAUTHORIZATIONRESULT
DESCRIPTOR.message_types_by_name['NotificationAuthorizationResult'] = _NOTIFICATIONAUTHORIZATIONRESULT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificationAuthorizationResult = _reflection.GeneratedProtocolMessageType('NotificationAuthorizationResult', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATIONAUTHORIZATIONRESULT,
  '__module__' : 'authorization_result_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificationAuthorizationResult)
  })
_sym_db.RegisterMessage(NotificationAuthorizationResult)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
