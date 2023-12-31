# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: bt_central_notification.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import bluetooth_pb2 as bluetooth__pb2

from bluetooth_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='bt_central_notification.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1d\x62t_central_notification.proto\x12\x11insta360.messages\x1a\x0f\x62luetooth.proto\"X\n NotificatoinDiscoverBTPeripheral\x12\x34\n\x0bperipherals\x18\x01 \x03(\x0b\x32\x1f.insta360.messages.BTPeripheral\"X\n!NotificatoinConnectedToPeripheral\x12\x33\n\nperipheral\x18\x01 \x01(\x0b\x32\x1f.insta360.messages.BTPeripheral\"Y\n\"NotificatoinDisconnectedPeripheral\x12\x33\n\nperipheral\x18\x01 \x01(\x0b\x32\x1f.insta360.messages.BTPeripheralB\x08\xa2\x02\x05INSPBP\x00\x62\x06proto3'
  ,
  dependencies=[bluetooth__pb2.DESCRIPTOR,],
  public_dependencies=[bluetooth__pb2.DESCRIPTOR,])




_NOTIFICATOINDISCOVERBTPERIPHERAL = _descriptor.Descriptor(
  name='NotificatoinDiscoverBTPeripheral',
  full_name='insta360.messages.NotificatoinDiscoverBTPeripheral',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='peripherals', full_name='insta360.messages.NotificatoinDiscoverBTPeripheral.peripherals', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  serialized_start=69,
  serialized_end=157,
)


_NOTIFICATOINCONNECTEDTOPERIPHERAL = _descriptor.Descriptor(
  name='NotificatoinConnectedToPeripheral',
  full_name='insta360.messages.NotificatoinConnectedToPeripheral',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='peripheral', full_name='insta360.messages.NotificatoinConnectedToPeripheral.peripheral', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=159,
  serialized_end=247,
)


_NOTIFICATOINDISCONNECTEDPERIPHERAL = _descriptor.Descriptor(
  name='NotificatoinDisconnectedPeripheral',
  full_name='insta360.messages.NotificatoinDisconnectedPeripheral',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='peripheral', full_name='insta360.messages.NotificatoinDisconnectedPeripheral.peripheral', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=249,
  serialized_end=338,
)

_NOTIFICATOINDISCOVERBTPERIPHERAL.fields_by_name['peripherals'].message_type = bluetooth__pb2._BTPERIPHERAL
_NOTIFICATOINCONNECTEDTOPERIPHERAL.fields_by_name['peripheral'].message_type = bluetooth__pb2._BTPERIPHERAL
_NOTIFICATOINDISCONNECTEDPERIPHERAL.fields_by_name['peripheral'].message_type = bluetooth__pb2._BTPERIPHERAL
DESCRIPTOR.message_types_by_name['NotificatoinDiscoverBTPeripheral'] = _NOTIFICATOINDISCOVERBTPERIPHERAL
DESCRIPTOR.message_types_by_name['NotificatoinConnectedToPeripheral'] = _NOTIFICATOINCONNECTEDTOPERIPHERAL
DESCRIPTOR.message_types_by_name['NotificatoinDisconnectedPeripheral'] = _NOTIFICATOINDISCONNECTEDPERIPHERAL
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NotificatoinDiscoverBTPeripheral = _reflection.GeneratedProtocolMessageType('NotificatoinDiscoverBTPeripheral', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATOINDISCOVERBTPERIPHERAL,
  '__module__' : 'bt_central_notification_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificatoinDiscoverBTPeripheral)
  })
_sym_db.RegisterMessage(NotificatoinDiscoverBTPeripheral)

NotificatoinConnectedToPeripheral = _reflection.GeneratedProtocolMessageType('NotificatoinConnectedToPeripheral', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATOINCONNECTEDTOPERIPHERAL,
  '__module__' : 'bt_central_notification_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificatoinConnectedToPeripheral)
  })
_sym_db.RegisterMessage(NotificatoinConnectedToPeripheral)

NotificatoinDisconnectedPeripheral = _reflection.GeneratedProtocolMessageType('NotificatoinDisconnectedPeripheral', (_message.Message,), {
  'DESCRIPTOR' : _NOTIFICATOINDISCONNECTEDPERIPHERAL,
  '__module__' : 'bt_central_notification_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.NotificatoinDisconnectedPeripheral)
  })
_sym_db.RegisterMessage(NotificatoinDisconnectedPeripheral)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
