# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
import os
from distutils.util import strtobool

import six
from six import iteritems

from canonicaljson import json


logger = logging.getLogger(__name__)

# Whether we should use frozen_dict in FrozenEvent. Using frozen_dicts prevents
# bugs where we accidentally share e.g. signature dicts. However, converting a
# dict to frozen_dicts is expensive.
#
# NOTE: This is overridden by the configuration by the Synapse worker apps, but
# for the sake of tests, it is set here while it cannot be configured on the
# homeserver object itself.
USE_FROZEN_DICTS = strtobool(os.environ.get("SYNAPSE_USE_FROZEN_DICTS", "0"))


class _EventInternalMetadata(object):
    def __init__(self, internal_metadata_dict):
        self.__dict__ = dict(internal_metadata_dict)

    def get_dict(self):
        return dict(self.__dict__)

    def is_outlier(self):
        return getattr(self, "outlier", False)

    def is_invite_from_remote(self):
        return getattr(self, "invite_from_remote", False)

    def get_send_on_behalf_of(self):
        """Whether this server should send the event on behalf of another server.
        This is used by the federation "send_join" API to forward the initial join
        event for a server in the room.

        returns a str with the name of the server this event is sent on behalf of.
        """
        return getattr(self, "send_on_behalf_of", None)


def _event_dict_property(key):
    # We want to be able to use hasattr with the event dict properties.
    # However, (on python3) hasattr expects AttributeError to be raised. Hence,
    # we need to transform the KeyError into an AttributeError
    def getter(self):
        try:
            return self._event_dict[key]
        except KeyError:
            raise AttributeError(key)

    def setter(self, v):
        try:
            self._event_dict[key] = v
        except KeyError:
            raise AttributeError(key)

    def delete(self):
        try:
            del self._event_dict[key]
        except KeyError:
            raise AttributeError(key)

    return property(
        getter,
        setter,
        delete,
    )


class EventBase(object):
    def __init__(self, event_dict, signatures={}, unsigned={},
                 internal_metadata_dict={}, rejected_reason=None):
        self.signatures = signatures
        self.unsigned = unsigned
        self.rejected_reason = rejected_reason

        self._event_dict = event_dict

        self.internal_metadata = _EventInternalMetadata(
            internal_metadata_dict
        )

    auth_events = _event_dict_property("auth_events")
    depth = _event_dict_property("depth")
    content = _event_dict_property("content")
    hashes = _event_dict_property("hashes")
    origin = _event_dict_property("origin")
    origin_server_ts = _event_dict_property("origin_server_ts")
    prev_events = _event_dict_property("prev_events")
    prev_state = _event_dict_property("prev_state")
    redacts = _event_dict_property("redacts")
    room_id = _event_dict_property("room_id")
    sender = _event_dict_property("sender")
    user_id = _event_dict_property("sender")

    @property
    def membership(self):
        return self.content["membership"]

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self):
        d = dict(self._event_dict)
        d.update({
            "signatures": self.signatures,
            "unsigned": dict(self.unsigned),
        })

        return d

    def get(self, key, default=None):
        return self._event_dict.get(key, default)

    def get_internal_metadata_dict(self):
        return self.internal_metadata.get_dict()

    def get_pdu_json(self, time_now=None):
        pdu_json = self.get_dict()

        if time_now is not None and "age_ts" in pdu_json["unsigned"]:
            age = time_now - pdu_json["unsigned"]["age_ts"]
            pdu_json.setdefault("unsigned", {})["age"] = int(age)
            del pdu_json["unsigned"]["age_ts"]

        # This may be a frozen event
        pdu_json["unsigned"].pop("redacted_because", None)

        return pdu_json

    def __set__(self, instance, value):
        raise AttributeError("Unrecognized attribute %s" % (instance,))

    def __getitem__(self, field):
        return self._event_dict[field]

    def __contains__(self, field):
        return field in self._event_dict

    def items(self):
        return list(self._event_dict.items())

    def keys(self):
        return six.iterkeys(self._event_dict)

    def auth_event_ids(self):
        return [e for e, _ in self.auth_events]

    def prev_event_ids(self):
        return [e for e, _ in self.prev_events]


class FrozenEvent(object):
    __slots__ = (
        "_event_id",
        "_room_id",
        "_sender",
        "_event_type",
        "_state_key",
        "_redacts",
        "_depth",
        "_origin_server_ts",
        "_content",
        "_hashes",
        "_auth_event_ids",
        "_prev_event_ids",
        "_signatures",
        "unsigned",
        "_json",
        "rejected_reason",
        "internal_metadata",
    )

    def __init__(self, event_dict, internal_metadata_dict={}, rejected_reason=None):
        event_dict = dict(event_dict)  # We copy this as we're going to remove stuff

        # A lot of this is optional because the tests don't actually define them
        self._event_id = event_dict.get("event_id")
        self._room_id = event_dict.get("room_id")
        self._sender = event_dict.get("sender")
        self._event_type = event_dict.get("type")
        self._state_key = event_dict.get("state_key")
        self._depth = event_dict.get("depth")
        self._redacts = event_dict.get("redacts")
        self._origin_server_ts = event_dict.get("origin_server_ts")

        # TODO: We should replace this with something that can't be modified
        self._content = dict(event_dict.get("content", {}))

        # Some events apparently don't have a 'hashes' field
        # TODO: Can we compress this? Freeze it somehow?
        self._hashes = event_dict.get("hashes", {})

        self._auth_event_ids = tuple(e for e, _ in event_dict.get("auth_events", []))
        self._prev_event_ids = tuple(e for e, _ in event_dict.get("prev_events", []))

        # Signatures is a dict of dicts, and this is faster than doing a
        # copy.deepcopy
        # TODO: Can we compress this? We could convert the base64 to bytes?
        self._signatures = {
            name: {
                sig_id: sig
                for sig_id, sig in iteritems(sigs)
            }
            for name, sigs in iteritems(event_dict.pop("signatures", {}))
        }

        self.unsigned = event_dict.pop("unsigned", {})

        self._json = json.dumps(event_dict)

        self.rejected_reason = rejected_reason
        self.internal_metadata = _EventInternalMetadata(
            internal_metadata_dict
        )

    @property
    def event_id(self):
        return self._event_id

    @property
    def room_id(self):
        return self._room_id

    @property
    def sender(self):
        return self._sender

    @property
    def type(self):
        return self._event_type

    @property
    def state_key(self):
        if self._state_key is not None:
            return self._state_key
        raise AttributeError("state_key")

    @property
    def redacts(self):
        return self._redacts

    @property
    def origin_server_ts(self):
        return self._origin_server_ts

    @property
    def content(self):
        return self._content

    @property
    def hashes(self):
        return self._hashes

    @property
    def membership(self):
        return self.content["membership"]

    def auth_event_ids(self):
        return self._auth_event_ids

    def prev_event_ids(self):
        return self._prev_event_ids

    def room_version(self):
        raise NotImplementedError()

    @property
    def signatures(self):
        return self._signatures

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self):
        pdu_json = json.loads(self._json)
        pdu_json["unsigned"] = self.unsigned
        pdu_json["signatures"] = self.signatures
        # logger.info("get_dict returning %s", pdu_json)
        return pdu_json

    def get_pdu_json(self, time_now=None):
        pdu_json = self.get_dict()

        unsigned = dict(pdu_json["unsigned"])
        if time_now is not None and "age_ts" in unsigned:
            age = time_now - unsigned["age_ts"]
            unsigned["age"] = int(age)
            del unsigned["age_ts"]

        # This may be a frozen event
        unsigned.pop("redacted_because", None)

        pdu_json["unsigned"] = unsigned

        return pdu_json

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<FrozenEvent event_id='%s', type='%s', state_key='%s'>" % (
            self._event_id,
            self._event_type,
            self._state_key,
        )

    @staticmethod
    def from_event(event):
        e = FrozenEvent(
            event.get_pdu_json()
        )

        e.internal_metadata = event.internal_metadata

        return e

    # FIXME: We probably want to get rid of the below functions

    def get(self, key, default=None):
        keys = ("sender", "hashes", "state_key", "room_id", "type", "content")
        if key in keys:
            return getattr(self, key, default)
        logger.error("get called for %s", key)
        raise NotImplementedError(key)

    def items(self):
        return list(self.get_dict().items())

    def keys(self):
        return six.iterkeys(self.get_dict())

    @property
    def user_id(self):
        return self._sender

    @property
    def depth(self):
        return self._depth

    @property
    def prev_state(self):
        return []
