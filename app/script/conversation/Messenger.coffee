#
# Wire
# Copyright (C) 2016 Wire Swiss GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/.
#

window.z ?= {}
z.conversation ?= {}

class z.conversation.Messenger

  constructor: (@conversation_repository, @user_repository, @cryptography_repository) ->
    @logger = new z.util.Logger 'z.messaging.Messenger', z.config.LOGGER.OPTIONS

    @conversation_service = @conversation_repository.conversation_service

    @sending_queue = new z.conversation.SendingQueue()
    @sending_queue.pause()

    @conversation_service.client.request_queue_blocked_state.subscribe (state) =>
      @sending_queue.pause state isnt z.service.RequestQueueBlockedState.NONE and not @block_event_handling

  send_message: (conversation_et, generic_message, user_ids, native_push = true) =>
    return @sending_queue.push =>
      @_send_generic_message conversation_et, generic_message,user_ids, native_push

  ###
  Sends a generic message to a conversation.

  @private
  @param conversation_id [String] Conversation ID
  @param generic_message [z.protobuf.GenericMessage] Protobuf message to be encrypted and send
  @param user_ids [Array<String>] Optional array of user IDs to limit sending to
  @param native_push [Boolean] Optional if message should enforce native push
  @return [Promise] Promise that resolves when the message was sent
  ###
  _send_generic_message: (conversation_et, generic_message, user_ids, native_push = true) =>
    Promise.resolve @_send_as_external_message conversation_et, generic_message
    .then (send_as_external) =>
      if send_as_external
        @_send_external_generic_message conversation_et, generic_message, user_ids, native_push
      else
        skip_own_clients = generic_message.content is 'ephemeral'
        Promise.resolve @_create_user_client_map conversation_et, skip_own_clients
        .then (user_client_map) =>
          if user_ids
            delete user_client_map[user_id] for user_id of user_client_map when user_id not in user_ids
          if skip_own_clients
            user_ids = Object.keys user_client_map
          return @cryptography_repository.encrypt_generic_message user_client_map, generic_message
        .then (payload) =>
          payload.native_push = native_push
          @_send_encrypted_message conversation_et, generic_message, payload, user_ids
    .catch (error) =>
      if error.code is z.service.BackendClientError::STATUS_CODE.REQUEST_TOO_LARGE
        return @_send_external_generic_message conversation_et, generic_message, user_ids, native_push
      throw error

  ###
  Sends otr message to a conversation.

  @private
  @note Options for the precondition check on missing clients are:
    'false' - all clients, 'Array<String>' - only clients of listed users, 'true' - force sending
  @param conversation_id [String] Conversation ID
  @param generic_message [z.protobuf.GenericMessage] Protobuf message to be encrypted and send
  @param payload [Object]
  @param precondition_option [Array<String>|Boolean] Level that backend checks for missing clients
  @return [Promise] Promise that resolves after sending the encrypted message
  ###
  _send_encrypted_message: (conversation_et, generic_message, payload, precondition_option = false) =>
    @conversation_service.post_encrypted_message conversation_et.id, payload, precondition_option
    .then (response) =>
      @_handle_client_mismatch conversation_et, response # TODO
      return response
    .catch (error) =>
      throw error if not error.missing
      @_handle_client_mismatch conversation_et, error, generic_message, payload
      .then (updated_payload) =>
        return @conversation_service.post_encrypted_message conversation_et.id, updated_payload, true

  ###
  Send encrypted external message

  @param conversation_id [String] Conversation ID
  @param generic_message [z.protobuf.GenericMessage] Generic message to be sent as external message
  @param user_ids [Array<String>] Optional array of user IDs to limit sending to
  @param native_push [Boolean] Optional if message should enforce native push
  @return [Promise] Promise that resolves after sending the external message
  ###
  _send_external_generic_message: (conversation_et, generic_message, user_ids, native_push = true) =>
    z.assets.AssetCrypto.encrypt_aes_asset generic_message.toArrayBuffer()
    .then ([key_bytes, sha256, ciphertext]) =>
      skip_own_clients = generic_message.content is 'ephemeral'
      return @_create_user_client_map conversation_et, skip_own_clients
      .then (user_client_map) =>
        if user_ids
          delete user_client_map[user_id] for user_id of user_client_map when user_id not in user_ids
        if skip_own_clients
          user_ids = Object.keys user_client_map
        generic_message_external = new z.proto.GenericMessage z.util.create_random_uuid()
        generic_message_external.set 'external', new z.proto.External new Uint8Array(key_bytes), new Uint8Array(sha256)
        return @cryptography_repository.encrypt_generic_message user_client_map, generic_message_external
      .then (payload) =>
        payload.data = z.util.array_to_base64 ciphertext
        payload.native_push = native_push
        @_send_encrypted_message conversation_et, generic_message, payload, user_ids

  ###
  Estimate whether message should be send as type external.

  @private
  @param conversation_id [String]
  @param generic_message [z.protobuf.GenericMessage] Generic message that will be send
  @return [Boolean] Is payload likely to be too big so that we switch to type external?
  ###
  _send_as_external_message: (conversation_et, generic_message) ->
    estimated_number_of_clients = conversation_et.number_of_participants() * 4
    message_in_bytes = new Uint8Array(generic_message.toArrayBuffer()).length
    estimated_payload_in_bytes = estimated_number_of_clients * message_in_bytes
    return estimated_payload_in_bytes / 1024 > 200

  ###
  Handle client mismatch response from backend.

  @note As part of 412 or general response when sending encrypted message
  @param conversation_id [String] ID of conversation message was sent int
  @param client_mismatch [Object] Client mismatch object containing client user maps for deleted, missing and obsolete clients
  @param generic_message [z.proto.GenericMessage] Optionally the GenericMessage that was sent
  @param payload [Object] Optionally the initial payload that was sent resulting in a 412
  ###
  _handle_client_mismatch: (conversation_et, client_mismatch, generic_message, payload) =>
    Promise.resolve()
    .then =>
      if not _.isEmpty client_mismatch.redundant
        return @_handle_client_mismatch_obsolete client_mismatch.redundant, conversation_et, payload
      return payload
    .then (updated_payload) =>
      if not _.isEmpty client_mismatch.deleted
        return @_handle_client_mismatch_obsolete client_mismatch.deleted, false, updated_payload
      return updated_payload
    .then (updated_payload) =>
      if payload and not _.isEmpty client_mismatch.missing
        return @_handle_client_mismatch_missing client_mismatch.missing, generic_message, updated_payload
      return updated_payload

  _handle_client_mismatch_missing: (user_client_map, generic_message, payload) ->
    if _.isEmpty user_client_map
      return Promise.resolve payload

    save_promises = []

    @cryptography_repository.encrypt_generic_message user_client_map, generic_message, payload
    .then (updated_payload) =>
      payload = updated_payload
      for user_id, client_ids of user_client_map
        for client_id in client_ids
          save_promises.push @user_repository.add_client_to_user user_id, new z.client.Client {id: client_id}

      return Promise.all save_promises
    .then ->
      return payload

  _handle_client_mismatch_obsolete: (user_client_map, conversation_et, payload) ->
    if _.isEmpty user_client_map
      return Promise.resolve payload

    delete_promises = []
    for user_id, client_ids of user_client_map
      if conversation_et
        conversation_et.participating_user_ids.remove user_id
      else
        for client_id in client_ids
          delete payload.recipients[user_id][client_id] if payload
          delete_promises.push @user_repository.remove_client_from_user user_id, client_id

      if payload and (conversation_et or Object.keys(payload.recipients[user_id]).length is 0)
        delete payload.recipients[user_id]

    if conversation_et
      @conversation_repository.update_participating_user_ets conversation_et

    return Promise.all delete_promises
    .then ->
      return payload

  ###
  Create a user client map for a given conversation.

  @private
  @param conversation_id [String] Conversation ID
  @param skip_own_clients [Boolean] True, if other own clients should be skipped (to not sync messages on own clients)
  @return [Promise<Object>] Promise that resolves with a user client map
  ###
  _create_user_client_map: (conversation_et, skip_own_clients = false) ->
    user_client_map = {}
    user_ets = conversation_et.participating_user_ets()

    if not skip_own_clients
      user_ets.push @user_repository.self()

    for user_et in user_ets
      user_client_map[user_et.id] = (client_et.id for client_et in user_et.devices())

    return user_client_map
