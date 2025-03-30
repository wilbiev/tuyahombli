"""Support for Tuya Smart devices."""
from __future__ import annotations

from typing import NamedTuple

import requests
from tuya_iot import (
    AuthType,
    TuyaDevice,
    TuyaDeviceListener,
    TuyaDeviceManager,
    TuyaHomeManager,
    TuyaOpenAPI,
)

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_COUNTRY_CODE, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import dispatcher_send

from .const import (
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_APP_TYPE,
    CONF_AUTH_TYPE,
    CONF_ENDPOINT,
    DOMAIN,
    LOGGER,
    PLATFORMS,
    TUYA_DISCOVERY_NEW,
    TUYA_HA_SIGNAL_UPDATE_ENTITY,
)


class HomeAssistantTuyaData(NamedTuple):
    """Tuya data stored in the Home Assistant data object."""

    device_listener: TuyaDeviceListener
    device_manager: TuyaDeviceManager
    home_manager: TuyaHomeManager


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Async setup hass config entry."""
    hass.data.setdefault(DOMAIN, {})

    auth_type = AuthType(entry.data[CONF_AUTH_TYPE])
    api = TuyaOpenAPI(
        endpoint=entry.data[CONF_ENDPOINT],
        access_id=entry.data[CONF_ACCESS_ID],
        access_secret=entry.data[CONF_ACCESS_SECRET],
        auth_type=auth_type,
    )

    api.set_dev_channel("hass")

    try:
        if auth_type == AuthType.CUSTOM:
            response = await hass.async_add_executor_job(
                api.connect, entry.data[CONF_USERNAME], entry.data[CONF_PASSWORD]
            )
        else:
            response = await hass.async_add_executor_job(
                api.connect,
                entry.data[CONF_USERNAME],
                entry.data[CONF_PASSWORD],
                entry.data[CONF_COUNTRY_CODE],
                entry.data[CONF_APP_TYPE],
            )
    except requests.exceptions.RequestException as err:
        raise ConfigEntryNotReady(err) from err

    if response.get("success", False) is False:
        raise ConfigEntryNotReady(response)

    tuya_mq = TuyaOpenMQ_2(api)
    tuya_mq.start2()

    device_ids: set[str] = set()
    device_manager = TuyaDeviceManager(api, tuya_mq)
    home_manager = TuyaHomeManager(api, tuya_mq, device_manager)
    listener = DeviceListener(hass, device_manager, device_ids)
    device_manager.add_device_listener(listener)

    hass.data[DOMAIN][entry.entry_id] = HomeAssistantTuyaData(
        device_listener=listener,
        device_manager=device_manager,
        home_manager=home_manager,
    )

    # Get devices & clean up device entities
    await hass.async_add_executor_job(home_manager.update_device_cache)
    await cleanup_device_registry(hass, device_manager)

    # Register known device IDs
    device_registry = dr.async_get(hass)
    for device in device_manager.device_map.values():
        device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, device.id)},
            manufacturer="Tuya",
            name=device.name,
            model=f"{device.product_name} (unsupported)",
        )
        device_ids.add(device.id)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def cleanup_device_registry(
    hass: HomeAssistant, device_manager: TuyaDeviceManager
) -> None:
    """Remove deleted device registry entry if there are no remaining entities."""
    device_registry = dr.async_get(hass)
    for dev_id, device_entry in list(device_registry.devices.items()):
        for item in device_entry.identifiers:
            if item[0] == DOMAIN and item[1] not in device_manager.device_map:
                device_registry.async_remove_device(dev_id)
                break


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unloading the Tuya platforms."""
    unload = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload:
        hass_data: HomeAssistantTuyaData = hass.data[DOMAIN][entry.entry_id]
        hass_data.device_manager.mq.stop()
        hass_data.device_manager.remove_device_listener(hass_data.device_listener)

        hass.data[DOMAIN].pop(entry.entry_id)
        if not hass.data[DOMAIN]:
            hass.data.pop(DOMAIN)

    return unload


class DeviceListener(TuyaDeviceListener):
    """Device Update Listener."""

    def __init__(
        self,
        hass: HomeAssistant,
        device_manager: TuyaDeviceManager,
        device_ids: set[str],
    ) -> None:
        """Init DeviceListener."""
        self.hass = hass
        self.device_manager = device_manager
        self.device_ids = device_ids

    def update_device(self, device: TuyaDevice) -> None:
        """Update device status."""
        if device.id in self.device_ids:
            LOGGER.debug(
                "Received update for device %s: %s",
                device.id,
                self.device_manager.device_map[device.id].status,
            )
            dispatcher_send(self.hass, f"{TUYA_HA_SIGNAL_UPDATE_ENTITY}_{device.id}")

    def add_device(self, device: TuyaDevice) -> None:
        """Add device added listener."""
        # Ensure the device isn't present stale
        self.hass.add_job(self.async_remove_device, device.id)

        self.device_ids.add(device.id)
        dispatcher_send(self.hass, TUYA_DISCOVERY_NEW, [device.id])

        device_manager = self.device_manager
        device_manager.mq.stop()
        tuya_mq = TuyaOpenMQ_2(device_manager.api)
        tuya_mq.start2()

        device_manager.mq = tuya_mq
        tuya_mq.add_message_listener(device_manager.on_message)

    def remove_device(self, device_id: str) -> None:
        """Add device removed listener."""
        self.hass.add_job(self.async_remove_device, device_id)

    @callback
    def async_remove_device(self, device_id: str) -> None:
        """Remove device from Home Assistant."""
        LOGGER.debug("Remove device: %s", device_id)
        device_registry = dr.async_get(self.hass)
        device_entry = device_registry.async_get_device(
            identifiers={(DOMAIN, device_id)}
        )
        if device_entry is not None:
            device_registry.async_remove_device(device_entry.id)
            self.device_ids.discard(device_id)


class TuyaOpenMQ_2(threading.Thread):
    """Tuya open iot hub.

    Tuya open iot hub base on mqtt.

    Attributes:
      openapi: tuya openapi
    """

    def __init__(self, api: TuyaOpenAPI) -> None:
        """Init TuyaOpenMQ."""
        threading.Thread.__init__(self)
        self.api: TuyaOpenAPI = api
        self._stop_event = threading.Event()
        self.client = None
        self.mq_config = None
        self.message_listeners = set()

    def _get_mqtt_config(self) -> Optional[TuyaMQConfig]:
        response = self.api.post(
            TO_C_CUSTOM_MQTT_CONFIG_API
            if (self.api.auth_type == AuthType.CUSTOM)
            else TO_C_SMART_HOME_MQTT_CONFIG_API,
            {
                "uid": self.api.token_info.uid,
                "link_id": LINK_ID,
                "link_type": "mqtt",
                "topics": "device",
                "msg_encrypted_version": "2.0"
                if (self.api.auth_type == AuthType.CUSTOM)
                else "1.0",
            },
        )

        if response.get("success", False) is False:
            return None

        return TuyaMQConfig(response)

    def _decode_mq_message(self, b64msg: str, password: str, t: str) -> dict[str, Any]:
        key = password[8:24]

        if self.api.auth_type == AuthType.SMART_HOME:
            cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
            msg = cipher.decrypt(base64.b64decode(b64msg))
            padding_bytes = msg[-1]
            msg = msg[:-padding_bytes]
            return json.loads(msg)
        else:
            # base64 decode
            buffer = base64.b64decode(b64msg)

            # get iv buffer
            iv_length = int.from_bytes(buffer[0:4], byteorder="big")
            iv_buffer = buffer[4: iv_length + 4]

            # get data buffer
            data_buffer = buffer[iv_length + 4: len(buffer) - GCM_TAG_LENGTH]

            # aad
            aad_buffer = str(t).encode("utf8")

            # tag
            tag_buffer = buffer[len(buffer) - GCM_TAG_LENGTH:]

            cipher = AES.new(key.encode("utf8"), AES.MODE_GCM, nonce=iv_buffer)
            cipher.update(aad_buffer)
            plaintext = cipher.decrypt_and_verify(data_buffer, tag_buffer).decode(
                "utf8"
            )
            return json.loads(plaintext)

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            logger.error(f"Unexpected disconnection.{rc}")
        else:
            logger.debug("disconnect")

    def _on_connect(self, mqttc: mqtt.Client, user_data: Any, flags, rc):
        logger.debug(f"connect flags->{flags}, rc->{rc}")
        if rc == 0:
            for (key, value) in self.mq_config.source_topic.items():
                mqttc.subscribe(value)
        elif rc == CONNECT_FAILED_NOT_AUTHORISED:
            self.__run_mqtt()

    def _on_message(self, mqttc: mqtt.Client, user_data: Any, msg: mqtt.MQTTMessage):
        logger.debug(f"payload-> {msg.payload}")

        msg_dict = json.loads(msg.payload.decode("utf8"))

        t = msg_dict.get("t", "")

        mq_config = user_data["mqConfig"]
        decrypted_data = self._decode_mq_message(
            msg_dict["data"], mq_config.password, t
        )
        if decrypted_data is None:
            return

        msg_dict["data"] = decrypted_data
        logger.debug(f"on_message: {msg_dict}")

        for listener in self.message_listeners:
            listener(msg_dict)

    def _on_subscribe(self, mqttc: mqtt.Client, user_data: Any, mid, granted_qos):
        logger.debug(f"_on_subscribe: {mid}")

    def _on_log(self, mqttc: mqtt.Client, user_data: Any, level, string):
        logger.debug(f"_on_log: {string}")

    def run(self):
        """Method representing the thread's activity which should not be used directly."""
        backoff_seconds = 1
        while not self._stop_event.is_set():
            try:
                self.__run_mqtt()
                backoff_seconds = 1

                # reconnect every 2 hours required.
                time.sleep(self.mq_config.expire_time - 60)
            except RequestException as e:
                logger.exception(e)
                logger.error(f"failed to refresh mqtt server, retrying in {backoff_seconds} seconds.")

                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2 , 60) # Try at most every 60 seconds to refresh


    def __run_mqtt(self):
        mq_config = self._get_mqtt_config()
        if mq_config is None:
            logger.error("error while get mqtt config")
            return

        self.mq_config = mq_config

        logger.debug(f"connecting {mq_config.url}")
        mqttc = self._start(mq_config)

        if self.client:
            self.client.disconnect()
        self.client = mqttc

    def _start(self, mq_config: TuyaMQConfig) -> mqtt.Client:
        mqttc = mqtt.Client(client_id=mq_config.client_id)
        mqttc.username_pw_set(mq_config.username, mq_config.password)
        mqttc.user_data_set({"mqConfig": mq_config})
        mqttc.on_connect = self._on_connect
        mqttc.on_message = self._on_message
        mqttc.on_subscribe = self._on_subscribe
        mqttc.on_log = self._on_log
        mqttc.on_disconnect = self._on_disconnect

        url = urlsplit(mq_config.url)
        if url.scheme == "ssl":
            mqttc.tls_set()

        mqttc.connect(url.hostname, url.port)

        mqttc.loop_start()
        return mqttc

    def start(self):
        """Start mqtt.

        Start mqtt thread
        """
        logger.debug("start")
        super().start()

    def stop(self):
        """Stop mqtt.

        Stop mqtt thread
        """
        logger.debug("stop")
        self.message_listeners = set()
        self.client.disconnect()
        self.client = None
        self._stop_event.set()

    def add_message_listener(self, listener: Callable[[str], None]):
        """Add mqtt message listener."""
        self.message_listeners.add(listener)

    def remove_message_listener(self, listener: Callable[[str], None]):
        """Remvoe mqtt message listener."""
        self.message_listeners.discard(listener)