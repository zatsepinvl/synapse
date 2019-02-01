# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from six import iteritems

from canonicaljson import encode_canonical_json, json

from twisted.internet import defer

from signedjson.key import decode_verify_key_bytes
from signedjson.sign import SignatureVerifyException, verify_signed_json

from synapse.api.errors import Codes, CodeMessageException, FederationDeniedError, \
    SynapseError
from synapse.types import UserID, get_domain_from_id
from synapse.util.logcontext import make_deferred_yieldable, run_in_background
from synapse.util.retryutils import NotRetryingDestination

from unpaddedbase64 import decode_base64

logger = logging.getLogger(__name__)


class E2eKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.federation = hs.get_federation_client()
        self.device_handler = hs.get_device_handler()
        self.is_mine = hs.is_mine
        self.clock = hs.get_clock()

        # doesn't really work as part of the generic query API, because the
        # query request requires an object POST, but we abuse the
        # "query handler" interface.
        hs.get_federation_registry().register_query_handler(
            "client_keys", self.on_federation_query_client_keys
        )

    @defer.inlineCallbacks
    def query_devices(self, query_body, timeout, from_user_id=None):
        """ Handle a device key query from a client

        {
            "device_keys": {
                "<user_id>": ["<device_id>"]
            }
        }
        ->
        {
            "device_keys": {
                "<user_id>": {
                    "<device_id>": {
                        ...
                    }
                }
            }
        }

        Args:
            from_user_id (str): the user making the query.  This is used when
                adding cross-signing signatures to limit what signatures users
                can see.
        """
        device_keys_query = query_body.get("device_keys", {})

        # separate users by domain.
        # make a map from domain to user_id to device_ids
        local_query = {}
        remote_queries = {}

        for user_id, device_ids in device_keys_query.items():
            # we use UserID.from_string to catch invalid user ids
            if self.is_mine(UserID.from_string(user_id)):
                local_query[user_id] = device_ids
            else:
                remote_queries[user_id] = device_ids

        # First get local devices.
        failures = {}
        results = {}
        if local_query:
            local_result = yield self.query_local_devices(local_query)
            for user_id, keys in local_result.items():
                if user_id in local_query:
                    results[user_id] = keys

        # Now attempt to get any remote devices from our local cache.
        remote_queries_not_in_cache = {}
        if remote_queries:
            query_list = []
            for user_id, device_ids in iteritems(remote_queries):
                if device_ids:
                    query_list.extend((user_id, device_id) for device_id in device_ids)
                else:
                    query_list.append((user_id, None))

            user_ids_not_in_cache, remote_results = (
                yield self.store.get_user_devices_from_cache(
                    query_list
                )
            )
            for user_id, devices in iteritems(remote_results):
                user_devices = results.setdefault(user_id, {})
                for device_id, device in iteritems(devices):
                    keys = device.get("keys", None)
                    device_display_name = device.get("device_display_name", None)
                    if keys:
                        result = dict(keys)
                        unsigned = result.setdefault("unsigned", {})
                        if device_display_name:
                            unsigned["device_display_name"] = device_display_name
                        user_devices[device_id] = result

            for user_id in user_ids_not_in_cache:
                domain = get_domain_from_id(user_id)
                r = remote_queries_not_in_cache.setdefault(domain, {})
                r[user_id] = remote_queries[user_id]

        # Now fetch any devices that we don't have in our cache
        @defer.inlineCallbacks
        def do_remote_query(destination):
            destination_query = remote_queries_not_in_cache[destination]
            try:
                remote_result = yield self.federation.query_client_keys(
                    destination,
                    {"device_keys": destination_query},
                    timeout=timeout
                )

                for user_id, keys in remote_result["device_keys"].items():
                    if user_id in destination_query:
                        results[user_id] = keys

            except Exception as e:
                failures[destination] = _exception_to_failure(e)

        yield make_deferred_yieldable(defer.gatherResults([
            run_in_background(do_remote_query, destination)
            for destination in remote_queries_not_in_cache
        ], consumeErrors=True))

        self_signing_keys = {}

        @defer.inlineCallbacks
        def get_self_signing_key(user_id):
            try:
                self_signing_keys[user_id] = \
                    yield self.store.get_e2e_self_signing_key(user_id, from_user_id)
            except Exception as e:
                pass

        yield make_deferred_yieldable(defer.gatherResults([
            run_in_background(get_self_signing_key, user_id)
            for user_id in local_query.keys()
        ]))

        defer.returnValue({
            "device_keys": results, "failures": failures,
            "self_signing_keys": self_signing_keys,
        })

    @defer.inlineCallbacks
    def query_local_devices(self, query):
        """Get E2E device keys for local users

        Args:
            query (dict[string, list[string]|None): map from user_id to a list
                 of devices to query (None for all devices)

        Returns:
            defer.Deferred: (resolves to dict[string, dict[string, dict]]):
                 map from user_id -> device_id -> device details
        """
        local_query = []

        result_dict = {}
        for user_id, device_ids in query.items():
            # we use UserID.from_string to catch invalid user ids
            if not self.is_mine(UserID.from_string(user_id)):
                logger.warning("Request for keys for non-local user %s",
                               user_id)
                raise SynapseError(400, "Not a user here")

            if not device_ids:
                local_query.append((user_id, None))
            else:
                for device_id in device_ids:
                    local_query.append((user_id, device_id))

            # make sure that each queried user appears in the result dict
            result_dict[user_id] = {}

        results = yield self.store.get_e2e_device_keys(local_query)

        # Build the result structure, un-jsonify the results, and add the
        # "unsigned" section
        for user_id, device_keys in results.items():
            for device_id, device_info in device_keys.items():
                r = dict(device_info["keys"])
                r["unsigned"] = {}
                display_name = device_info["device_display_name"]
                if display_name is not None:
                    r["unsigned"]["device_display_name"] = display_name
                result_dict[user_id][device_id] = r

        defer.returnValue(result_dict)

    @defer.inlineCallbacks
    def on_federation_query_client_keys(self, query_body):
        """ Handle a device key query from a federated server
        """
        device_keys_query = query_body.get("device_keys", {})
        res = yield self.query_local_devices(device_keys_query)
        defer.returnValue({"device_keys": res})

    @defer.inlineCallbacks
    def claim_one_time_keys(self, query, timeout):
        local_query = []
        remote_queries = {}

        for user_id, device_keys in query.get("one_time_keys", {}).items():
            # we use UserID.from_string to catch invalid user ids
            if self.is_mine(UserID.from_string(user_id)):
                for device_id, algorithm in device_keys.items():
                    local_query.append((user_id, device_id, algorithm))
            else:
                domain = get_domain_from_id(user_id)
                remote_queries.setdefault(domain, {})[user_id] = device_keys

        results = yield self.store.claim_e2e_one_time_keys(local_query)

        json_result = {}
        failures = {}
        for user_id, device_keys in results.items():
            for device_id, keys in device_keys.items():
                for key_id, json_bytes in keys.items():
                    json_result.setdefault(user_id, {})[device_id] = {
                        key_id: json.loads(json_bytes)
                    }

        @defer.inlineCallbacks
        def claim_client_keys(destination):
            device_keys = remote_queries[destination]
            try:
                remote_result = yield self.federation.claim_client_keys(
                    destination,
                    {"one_time_keys": device_keys},
                    timeout=timeout
                )
                for user_id, keys in remote_result["one_time_keys"].items():
                    if user_id in device_keys:
                        json_result[user_id] = keys
            except Exception as e:
                failures[destination] = _exception_to_failure(e)

        yield make_deferred_yieldable(defer.gatherResults([
            run_in_background(claim_client_keys, destination)
            for destination in remote_queries
        ], consumeErrors=True))

        logger.info(
            "Claimed one-time-keys: %s",
            ",".join((
                "%s for %s:%s" % (key_id, user_id, device_id)
                for user_id, user_keys in iteritems(json_result)
                for device_id, device_keys in iteritems(user_keys)
                for key_id, _ in iteritems(device_keys)
            )),
        )

        defer.returnValue({
            "one_time_keys": json_result,
            "failures": failures
        })

    @defer.inlineCallbacks
    def upload_keys_for_user(self, user_id, device_id, keys):
        time_now = self.clock.time_msec()

        # TODO: Validate the JSON to make sure it has the right keys.
        device_keys = keys.get("device_keys", None)
        if device_keys:
            logger.info(
                "Updating device_keys for device %r for user %s at %d",
                device_id, user_id, time_now
            )
            # TODO: Sign the JSON with the server key
            changed = yield self.store.set_e2e_device_keys(
                user_id, device_id, time_now, device_keys,
            )
            if changed:
                # Only notify about device updates *if* the keys actually changed
                yield self.device_handler.notify_device_update(user_id, [device_id])

        one_time_keys = keys.get("one_time_keys", None)
        if one_time_keys:
            yield self._upload_one_time_keys_for_user(
                user_id, device_id, time_now, one_time_keys,
            )

        # the device should have been registered already, but it may have been
        # deleted due to a race with a DELETE request. Or we may be using an
        # old access_token without an associated device_id. Either way, we
        # need to double-check the device is registered to avoid ending up with
        # keys without a corresponding device.
        yield self.device_handler.check_device_registered(user_id, device_id)

        result = yield self.store.count_e2e_one_time_keys(user_id, device_id)

        defer.returnValue({"one_time_key_counts": result})

    @defer.inlineCallbacks
    def _upload_one_time_keys_for_user(self, user_id, device_id, time_now,
                                       one_time_keys):
        logger.info(
            "Adding one_time_keys %r for device %r for user %r at %d",
            one_time_keys.keys(), device_id, user_id, time_now,
        )

        # make a list of (alg, id, key) tuples
        key_list = []
        for key_id, key_obj in one_time_keys.items():
            algorithm, key_id = key_id.split(":")
            key_list.append((
                algorithm, key_id, key_obj
            ))

        # First we check if we have already persisted any of the keys.
        existing_key_map = yield self.store.get_e2e_one_time_keys(
            user_id, device_id, [k_id for _, k_id, _ in key_list]
        )

        new_keys = []  # Keys that we need to insert. (alg, id, json) tuples.
        for algorithm, key_id, key in key_list:
            ex_json = existing_key_map.get((algorithm, key_id), None)
            if ex_json:
                if not _one_time_keys_match(ex_json, key):
                    raise SynapseError(
                        400,
                        ("One time key %s:%s already exists. "
                         "Old key: %s; new key: %r") %
                        (algorithm, key_id, ex_json, key)
                    )
            else:
                new_keys.append((
                    algorithm, key_id, encode_canonical_json(key).decode('ascii')))

        yield self.store.add_e2e_one_time_keys(
            user_id, device_id, time_now, new_keys
        )

    @defer.inlineCallbacks
    def upload_signing_keys_for_user(self, user_id, keys):
        """Upload signing keys for cross-signing

        Args:
            user_id (string): the user uploading the keys
            keys (dict[string, dict]): the signing keys
        """
        old_self_signing_key = yield self.store.get_e2e_self_signing_key(user_id)

        if "self_signing_key" in keys:
            self_signing_key = keys["self_signing_key"]

            # basic sanity checking
            if self_signing_key["user_id"] != user_id \
               or "self_signing" not in self_signing_key["usage"]:
                raise SynapseError(
                    400,
                    "Invalid self-signing key",
                    Codes.INVALID_PARAM
                )

            # if we have a previous self-signing key, make sure that it is
            # acknowledged, to prevent users from accidentally overwriting a
            # key
            if old_self_signing_key:
                if "replaces" not in self_signing_key:
                    raise SynapseError(
                        400,
                        "A self-signing key already exists",
                        "M_NEEDS_REPLACES"
                    )
                old_key_id, old_verify_key \
                    = _get_verify_key_from_key_info(old_self_signing_key)
                if self_signing_key["replaces"] != old_key_id.split(':', 1)[1]:
                    raise SynapseError(
                        400,
                        "Incorrect replaces property",
                        "M_BAD_REPLACES"
                    )

            # if the key is signed, it must be signed by the old self-signing
            # key, and we check that it is a valid signature
            if "signatures" in self_signing_key:
                if not old_self_signing_key:
                    raise SynapseError(
                        400,
                        "Invalid signature",
                        Codes.INVALID_SIGNATURE
                    )
                old_key_id, old_verify_key \
                    = _get_verify_key_from_key_info(old_self_signing_key)
                if user_id not in self_signing_key["signatures"] \
                   or old_key_id not in self_signing_key["signatures"][user_id]:
                    raise SynapseError(
                        400,
                        "Invalid signature on self-signing key",
                        Codes.INVALID_SIGNATURE
                    )
                try:
                    verify_signed_json(self_signing_key, user_id, old_verify_key)
                except SignatureVerifyException as e:
                    raise SynapseError(
                        400,
                        "Invalid signature on self-signing key",
                        Codes.INVALID_SIGNATURE
                    )
        else:
            self_signing_key = old_self_signing_key

        key_id, verify_key = _get_verify_key_from_key_info(self_signing_key)

        if "user_signing_key" in keys:
            user_signing_key = keys["user_signing_key"]

            # basic sanity checking
            if user_signing_key["user_id"] != user_id \
               or "user_signing" not in user_signing_key["usage"]:
                raise SynapseError(
                    400,
                    "Invalid user-signing key",
                    Codes.INVALID_PARAM
                )

            # the user-signing key must be signed by the current self-signing key
            if "signatures" not in user_signing_key\
               or user_id not in user_signing_key["signatures"] \
               or key_id not in user_signing_key["signatures"][user_id]:
                raise SynapseError(
                    400,
                    "Invalid signature on user-signing key",
                    Codes.INVALID_SIGNATURE
                )
            try:
                verify_signed_json(user_signing_key, user_id, verify_key)
            except SignatureVerifyException as e:
                raise SynapseError(
                    400,
                    "Invalid signature on user-signing key",
                    Codes.INVALID_SIGNATURE
                )

        # if everything checks out, then store the keys and send notifications
        deviceids = []
        if "self_signing_key" in keys:
            yield self.store.set_e2e_self_signing_key(user_id, self_signing_key)
            deviceids.append(key_id)
        if "user_signing_key" in keys:
            yield self.store.set_e2e_user_signing_key(user_id, user_signing_key)
            deviceids.append(_get_verify_key_from_key_info(user_signing_key)[0])

        if len(deviceids):
            yield self.device_handler.notify_device_update(user_id, deviceids)

        defer.returnValue({})

    @defer.inlineCallbacks
    def upload_signatures_for_device_keys(self, user_id, signatures):
        """Upload signatures for cross-signing

        Args:
            user_id (string): the user uploading the signatures
            signatures (dict[string, dict[string, dict]]): map of users to
                devices to signed keys
        """
        failures = {}

        signature_list = []   # signatures to be stored
        self_device_ids = []  # what devices have been updated, for notifying

        # split between checking signatures for own user and signatures for
        # other users, since we verify them with different keys
        if user_id in signatures:
            self_signatures = signatures[user_id]
            del signatures[user_id]
            self_device_ids = list(self_signatures.keys())
            try:
                # get our self-signing key to verify the signatures
                self_signing_key = yield self.store.get_e2e_self_signing_key(user_id)
                if self_signing_key is None:
                    raise SynapseError(
                        404,
                        "No self-signing key found",
                        Codes.NOT_FOUND
                    )

                self_signing_key_id, self_signing_verify_key \
                    = _get_verify_key_from_key_info(self_signing_key)

                # fetch our devices so that we can compare with what was sent
                user_devices = []
                for device in self_signatures.keys():
                    user_devices.append((user_id, device))
                devices = yield self.store.get_e2e_device_keys(user_devices)

                if user_id not in devices:
                    raise SynapseError(
                        404,
                        "No device key found",
                        Codes.NOT_FOUND
                    )

                devices = devices[user_id]
                for device, key in self_signatures.items():
                    try:
                        if ("signatures" not in key or user_id not in key["signatures"]
                                or self_signing_key_id not in key["signatures"][user_id]):
                            raise SynapseError(
                                400,
                                "Invalid signature",
                                Codes.INVALID_SIGNATURE
                            )

                        signature = key["signatures"][user_id][self_signing_key_id]

                        # make sure that the key submitted matches what we have stored
                        del key["signatures"]
                        if "unsigned" in key:
                            del key["unsigned"]
                        stored_key = devices[device]["keys"]
                        if "signatures" in stored_key:
                            del stored_key["signatures"]
                        if "unsigned" in stored_key:
                            del stored_key["unsigned"]
                        if key != stored_key:
                            logger.error(
                                "upload signatures: key does not match %s vs %s",
                                key, stored_key
                            )
                            raise SynapseError(
                                400,
                                "Key does not match",
                                "M_MISMATCHED_KEY"
                            )

                        # verify the signature
                        key["signatures"] = {
                            user_id: {
                                self_signing_key_id: signature
                            }
                        }
                        try:
                            verify_signed_json(key, user_id, self_signing_verify_key)
                        except SignatureVerifyException as e:
                            logger.error("invalid signature on key")
                            raise SynapseError(
                                400,
                                "Invalid signature",
                                Codes.INVALID_SIGNATURE
                            )

                        signature_list.append(
                            (self_signing_key_id, user_id, device, signature)
                        )
                    except SynapseError as e:
                        failures.setdefault(user_id, {})[device] \
                            = _exception_to_failure(e)
            except SynapseError as e:
                failures[user_id] = {
                    device: _exception_to_failure(e)
                    for device in self_signatures.keys()
                }

        signed_users = []  # what user have been signed, for notifying
        if len(signatures):
            # if signatures isn't empty, then we have signatures for other
            # users.  These signatures will be signed by the user signing key

            # get our user-signing key to verify the signatures
            user_signing_key = yield self.store.get_e2e_user_signing_key(user_id)
            if user_signing_key is None:
                for user, devicemap in signatures.items():
                    failures[user] = {
                        device: _exception_to_failure(SynapseError(
                            404,
                            "No user-signing key found",
                            Codes.NOT_FOUND
                        ))
                        for device in devicemap.keys()
                    }
            else:
                user_signing_key_id, user_signing_verify_key \
                    = _get_verify_key_from_key_info(user_signing_key)

                for user, devicemap in signatures.items():
                    device = None
                    try:
                        # get the user's self-signing key, to make sure it
                        # matches what was sent
                        user_key = yield self.store.get_e2e_self_signing_key(user)
                        if user_key is None:
                            logger.error(
                                "upload signature: no user key found for %s", user
                            )
                            raise SynapseError(
                                404,
                                "User's self-signing key not found",
                                Codes.NOT_FOUND
                            )

                        # make sure that the user's self-signing key is the one
                        # that was signed
                        device = _get_verify_key_from_key_info(user_key)[0] \
                            .split(":", 1)[1]
                        if device not in devicemap:
                            logger.error(
                                "upload signature: wrong device: %s vs %s",
                                device, devicemap
                            )
                            raise SynapseError(
                                404,
                                "Unknown device",
                                Codes.NOT_FOUND
                            )
                        key = devicemap[device]
                        del devicemap[device]

                        if len(devicemap) > 0:
                            logger.error("upload signature: too many devices specified")
                            failures[user] = {
                                device: _exception_to_failure(SynapseError(
                                    404,
                                    "Unknown device",
                                    Codes.NOT_FOUND
                                ))
                                for device in devicemap.keys()
                            }

                        # check that we have a signature
                        if ("signatures" not in key or user_id not in key["signatures"]
                                or user_signing_key_id not in key["signatures"][user_id]):
                            logger.error("upload signature: user not found in signatures")
                            raise SynapseError(
                                400,
                                "Invalid signature",
                                Codes.INVALID_SIGNATURE
                            )

                        signature = key["signatures"][user_id][user_signing_key_id]

                        # make sure that what was submitted matches the key that we have
                        del key["signatures"]
                        if "unsigned" in key:
                            del key["unsigned"]
                        if "signatures" in user_key:
                            del user_key["signatures"]
                        if "unsigned" in user_key:
                            del user_key["unsigned"]
                        if key != user_key:
                            # FIXME: error
                            logger.error(
                                "upload signature: key does not match %s vs %s",
                                key, user_key
                            )
                            raise SynapseError(
                                400,
                                "Key does not match",
                                "M_MISMATCHED_KEY"
                            )

                        # verify the signature
                        key["signatures"] = {
                            user_id: {
                                user_signing_key_id: signature
                            }
                        }
                        try:
                            verify_signed_json(key, user_id, user_signing_verify_key)
                        except SignatureVerifyException as e:
                            logger.error("invalid signature on key")
                            raise SynapseError(
                                400,
                                "Invalid signature",
                                Codes.M_INVALID_SIGNATURE
                            )

                        signed_users.append(user)
                        signature_list.append(
                            (user_signing_key_id, user, device, signature)
                        )
                    except SynapseError as e:
                        if device is None:
                            failures[user] = {
                                device: _exception_to_failure(e)
                                for device in devicemap.keys()
                            }
                        else:
                            failures.setdefault(user, {})[device] \
                                = _exception_to_failure(e)

        # store the signature, and send the appropriate notifications for sync
        yield self.store.store_e2e_device_signatures(user_id, signature_list)

        if len(self_device_ids):
            yield self.device_handler.notify_device_update(user_id, self_device_ids)
        if len(signed_users):
            yield self.device_handler.notify_user_signature_update(user_id, signed_users)

        defer.returnValue({"failures": failures})


def _get_verify_key_from_key_info(key_info):
    """Get the key ID and signedjson verify key from a cross-signing key dict

    Args:
        key_info (dict): a cross-signing key dict, which must have a "keys"
            property that has exactly one item in it
    """
    if "keys" not in key_info:
        raise SynapseError(
            400,
            "Invalid key"
        )
    keys = key_info["keys"]
    if len(keys) != 1:
        raise SynapseError(
            400,
            "Invalid key"
        )
    for key_id, key_data in keys.items():
        return (key_id, decode_verify_key_bytes(key_id, decode_base64(key_data)))


def _exception_to_failure(e):
    if isinstance(e, CodeMessageException):
        return {
            "status": e.code, "message": str(e),
        }

    if isinstance(e, NotRetryingDestination):
        return {
            "status": 503, "message": "Not ready for retry",
        }

    if isinstance(e, FederationDeniedError):
        return {
            "status": 403, "message": "Federation Denied",
        }

    # include ConnectionRefused and other errors
    #
    # Note that some Exceptions (notably twisted's ResponseFailed etc) don't
    # give a string for e.message, which json then fails to serialize.
    return {
        "status": 503, "message": str(e),
    }


def _one_time_keys_match(old_key_json, new_key):
    old_key = json.loads(old_key_json)

    # if either is a string rather than an object, they must match exactly
    if not isinstance(old_key, dict) or not isinstance(new_key, dict):
        return old_key == new_key

    # otherwise, we strip off the 'signatures' if any, because it's legitimate
    # for different upload attempts to have different signatures.
    old_key.pop("signatures", None)
    new_key_copy = dict(new_key)
    new_key_copy.pop("signatures", None)

    return old_key == new_key_copy
