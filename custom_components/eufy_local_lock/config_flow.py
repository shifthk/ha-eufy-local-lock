"""Set up a lock: one eufy login (with its e-mailed code or captcha), pick the lock,
confirm its LAN address. The login's session cache is kept, so the integration
starts without contacting eufy again."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from eufy_home_security import EufySecurity
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.exceptions import (
    AuthenticationError,
    EufySecurityError,
    LoginChallengeError,
    LoginVerificationError,
)
from eufy_home_security.storage import MemoryStore

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_EMAIL, CONF_HOST, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
    CONF_CLOUD_WAKE,
    CONF_COUNTRY,
    CONF_POLL_MINUTES,
    CONF_SERIAL,
    CONF_SHORT_USER_ID,
    CONF_USER_NAME,
    DEFAULT_POLL_MINUTES,
    DOMAIN,
    MAX_POLL_MINUTES,
    MIN_POLL_MINUTES,
)
from homeassistant.exceptions import ConfigEntryNotReady

from .hub import EntryStore, async_lock_details, build_account
from .smartlock import is_smart_lock_t8520p

_LOGGER = logging.getLogger(__name__)

CONF_CODE = "code"


def _member(device: CloudDevice) -> Mapping[str, Any]:
    member = device.raw.get("member")
    return member if isinstance(member, Mapping) else {}


class EufyLocalLockConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._store = MemoryStore()
        self._account: EufySecurity | None = None
        self._challenge: LoginChallengeError | None = None
        self._locks: dict[str, CloudDevice] = {}
        self._reauth_entry: ConfigEntry | None = None
        self._errors: dict[str, str] = {}
        """Errors to show on the next login form (a refused code restarts the login)."""

    # -- login ---------------------------------------------------------------------

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors, self._errors = self._errors, {}
        if user_input is not None:
            self._data = {
                CONF_EMAIL: user_input[CONF_EMAIL].strip(),
                CONF_PASSWORD: user_input[CONF_PASSWORD],
                CONF_COUNTRY: user_input.get(CONF_COUNTRY) or self.hass.config.country or "",
            }
            result = await self._async_login({}, errors)
            if result is not None:
                return result
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL, default=self._data.get(CONF_EMAIL, "")): str,
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    ),
                    vol.Optional(
                        CONF_COUNTRY, default=self.hass.config.country or ""
                    ): selector.CountrySelector(),
                }
            ),
            errors=errors,
        )

    async def async_step_challenge(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        challenge = self._challenge
        assert challenge is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            code = user_input[CONF_CODE].strip()
            answer = (
                {"verify_code": code, "login_id": challenge.login_id}
                if challenge.kind == "verify_code"
                else {
                    "captcha_id": challenge.captcha_id,
                    "captcha_answer": code,
                    "login_id": challenge.login_id,
                }
            )
            result = await self._async_login(answer, errors)
            if result is not None:
                return result
            if self._challenge is None:
                # eufy dropped the pending verification: a plain login starts over.
                self._errors = errors
                if self._reauth_entry is not None:
                    return await self.async_step_reauth_confirm()
                return await self.async_step_user()
        captcha = challenge.kind == "captcha"
        return self.async_show_form(
            step_id="challenge",
            data_schema=vol.Schema({vol.Required(CONF_CODE): str}),
            description_placeholders={
                "prompt": (
                    f"Type the characters in this image:\n\n![captcha]({challenge.captcha_image})"
                    if captcha
                    else "eufy has e-mailed you a verification code. Enter it here."
                )
            },
            errors=errors,
        )

    async def _async_login(
        self, answer: dict[str, str], errors: dict[str, str]
    ) -> ConfigFlowResult | None:
        """Log in (or answer a challenge); a result to return, or None to show errors."""
        if self._account is None:
            self._account = build_account(self.hass, self._data, self._store)
        try:
            await self._account.async_login(**answer, force=True)
        except LoginChallengeError as challenge:
            if challenge.kind not in ("verify_code", "captcha"):
                errors["base"] = "unknown"
                return None
            self._challenge = challenge
            return await self.async_step_challenge()
        except LoginVerificationError:
            errors["base"] = "invalid_code"
            self._challenge = None
            return None
        except AuthenticationError:
            errors["base"] = "invalid_auth"
            return None
        except EufySecurityError as err:
            _LOGGER.warning("eufy login failed: %s", err)
            errors["base"] = "cannot_connect"
            return None
        except Exception:
            _LOGGER.exception("unexpected error logging in to eufy")
            errors["base"] = "unknown"
            return None
        if self._reauth_entry is not None:
            return await self._async_finish_reauth()
        return await self.async_step_pick()

    # -- choose the lock -----------------------------------------------------------

    async def async_step_pick(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        assert self._account is not None
        if not self._locks:
            try:
                devices = await self._account.cloud.async_get_devices(refresh=True)
            except EufySecurityError as err:
                _LOGGER.warning("could not list eufy devices: %s", err)
                return self.async_abort(reason="cannot_connect")
            self._locks = {
                d.device_sn: d for d in devices if d.is_station and is_smart_lock_t8520p(d.device_sn)
            }
            if not self._locks:
                others = sorted(d.device_sn[:5] for d in devices if d.device_sn.startswith("T85"))
                return self.async_abort(
                    reason="no_supported_locks",
                    description_placeholders={"models": ", ".join(others) or "none"},
                )
        if user_input is None and len(self._locks) > 1:
            return self.async_show_form(
                step_id="pick",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_SERIAL): vol.In(
                            {sn: f"{d.name or 'Lock'} ({sn})" for sn, d in self._locks.items()}
                        )
                    }
                ),
            )
        serial = user_input[CONF_SERIAL] if user_input else next(iter(self._locks))
        await self.async_set_unique_id(serial)
        self._abort_if_unique_id_configured()
        self._data[CONF_SERIAL] = serial
        return await self.async_step_host()

    async def async_step_host(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        assert self._account is not None
        device = self._locks[self._data[CONF_SERIAL]]
        errors: dict[str, str] = {}
        if user_input is not None:
            member = await self._async_member(device)
            short_id = str(member.get("short_user_id") or "")
            if not short_id:
                return self.async_abort(reason="no_short_user_id")
            self._data.update(
                {
                    CONF_HOST: user_input.get(CONF_HOST, "").strip() or None,
                    CONF_SHORT_USER_ID: short_id,
                    CONF_USER_NAME: str(
                        member.get("nick_name")
                        or self._account.cloud.nick_name
                        or self._account.cloud.user_name
                    ),
                }
            )
            # Everything the lock is reached with afterwards, so that the
            # integration need not contact eufy again.
            try:
                self._data.update(await async_lock_details(self._account, self._data[CONF_SERIAL]))
            except (EufySecurityError, ConfigEntryNotReady) as err:
                _LOGGER.warning("could not read the lock's details from eufy: %s", err)
                return self.async_abort(reason="cannot_connect")
            # Keep the login's session cache for the integration, keyed by lock.
            cache = await self._store.async_load()
            if cache is not None:
                await EntryStore(self.hass, self._data[CONF_SERIAL]).async_save(cache)
            await self._account.async_close()
            return self.async_create_entry(title=device.name or "eufy lock", data=self._data)
        return self.async_show_form(
            step_id="host",
            data_schema=vol.Schema(
                {vol.Optional(CONF_HOST, default=device.local_ip or ""): str}
            ),
            description_placeholders={"name": device.name or device.device_sn},
            errors=errors,
        )

    async def _async_member(self, device: CloudDevice) -> Mapping[str, Any]:
        """This account's ``member`` entry at the lock: the house list's, else the
        security realm's station list (``get_hub_list``, what the eufy app reads)."""
        member = _member(device)
        if member.get("short_user_id"):
            return member
        assert self._account is not None
        try:
            hubs = await self._account.cloud.async_list_security_devices(
                device.region or self._account.cloud.region, stations=True
            )
        except EufySecurityError as err:
            _LOGGER.warning("could not read the eufy station list: %s", err)
            return member
        for hub in hubs:
            if device.device_sn in (hub.device_sn, hub.raw.get("station_sn")):
                found = _member(hub)
                if found.get("short_user_id"):
                    return {**member, **found}
        return member

    # -- reauth --------------------------------------------------------------------

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        self._reauth_entry = self._get_reauth_entry()
        self._data = dict(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors, self._errors = self._errors, {}
        if user_input is not None:
            self._data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
            result = await self._async_login({}, errors)
            if result is not None:
                return result
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    )
                }
            ),
            description_placeholders={"email": self._data.get(CONF_EMAIL, "")},
            errors=errors,
        )

    async def _async_finish_reauth(self) -> ConfigFlowResult:
        entry = self._reauth_entry
        assert entry is not None and self._account is not None
        cache = await self._store.async_load()
        if cache is not None:
            await EntryStore(self.hass, entry.data[CONF_SERIAL]).async_save(cache)
        await self._account.async_close()
        return self.async_update_reload_and_abort(
            entry, data_updates={CONF_PASSWORD: self._data[CONF_PASSWORD]}
        )

    # -- options -------------------------------------------------------------------

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return EufyLocalLockOptionsFlow()


class EufyLocalLockOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            user_input[CONF_HOST] = user_input.get(CONF_HOST, "").strip() or None
            return self.async_create_entry(data=user_input)
        entry = self.config_entry
        host = entry.options.get(CONF_HOST) or entry.data.get(CONF_HOST) or ""
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_HOST, default=host): str,
                    vol.Required(
                        CONF_POLL_MINUTES,
                        default=entry.options.get(CONF_POLL_MINUTES, DEFAULT_POLL_MINUTES),
                    ): vol.All(
                        vol.Coerce(int), vol.Range(min=MIN_POLL_MINUTES, max=MAX_POLL_MINUTES)
                    ),
                    vol.Required(
                        CONF_CLOUD_WAKE, default=entry.options.get(CONF_CLOUD_WAKE, False)
                    ): bool,
                }
            ),
        )
