# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: cancel_request_authorization.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import authorization_operation_type_pb2 as authorization__operation__type__pb2

from authorization_operation_type_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='cancel_request_authorization.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\"cancel_request_authorization.proto\x12\x11insta360.messages\x1a\"authorization_operation_type.proto\"q\n\x1a\x43\x61ncelRequestAuthorization\x12S\n\x1c\x61uthorization_operation_type\x18\x01 \x01(\x0e\x32-.insta360.messages.AuthorizationOperationTypeB\x08\xa2\x02\x05INSPBP\x00\x62\x06proto3'
  ,
  dependencies=[authorization__operation__type__pb2.DESCRIPTOR,],
  public_dependencies=[authorization__operation__type__pb2.DESCRIPTOR,])




_CANCELREQUESTAUTHORIZATION = _descriptor.Descriptor(
  name='CancelRequestAuthorization',
  full_name='insta360.messages.CancelRequestAuthorization',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='authorization_operation_type', full_name='insta360.messages.CancelRequestAuthorization.authorization_operation_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
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
  serialized_start=93,
  serialized_end=206,
)

_CANCELREQUESTAUTHORIZATION.fields_by_name['authorization_operation_type'].enum_type = authorization__operation__type__pb2._AUTHORIZATIONOPERATIONTYPE
DESCRIPTOR.message_types_by_name['CancelRequestAuthorization'] = _CANCELREQUESTAUTHORIZATION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CancelRequestAuthorization = _reflection.GeneratedProtocolMessageType('CancelRequestAuthorization', (_message.Message,), {
  'DESCRIPTOR' : _CANCELREQUESTAUTHORIZATION,
  '__module__' : 'cancel_request_authorization_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.CancelRequestAuthorization)
  })
_sym_db.RegisterMessage(CancelRequestAuthorization)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
