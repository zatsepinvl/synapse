# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

import attr
from sentry_sdk import Hub
from sentry_sdk.integrations import Integration

from synapse.util.logcontext import add_logcontext_hook


@attr.s(slots=True)
class SentryLogContextHook(object):
    """A logcontext hook that creates a new Hub for each top level logcontext
    """
    hub = attr.ib()

    @classmethod
    def create(cls, is_top_level):
        if not is_top_level:
            return None

        current_hub = Hub.current

        hub = Hub(current_hub)
        return cls(hub)

    def start(self):
        self.hub.__enter__()

    def stop(self):
        self.hub.__exit__(None, None, None)


class TwistedIntegration(Integration):
    identifier = "matrix-twisted"

    @staticmethod
    def setup_once():
        add_logcontext_hook(SentryLogContextHook)
