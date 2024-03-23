# home-assistant-tuya-hombli

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://github.com/hacs/integration)

A Home Assistant integration for adding custom Tuya categories without waiting for Core to update.
This code Home Assistanmt Core pull request and to allow quick additon of more devices.

This version supports the Hombli Smart Water Controller (Wifi Gateway/Bluetooth Controller).

## Instructions for installation:

### Setup Tuya integration

Follow the steps to create the [Tuya integration](https://github.com/tuya/tuya-home-assistant/blob/main/docs/install.md) and [Tuya IoT Platform Configuration Guide](https://github.com/tuya/tuya-home-assistant/blob/main/docs/install.md)

### Setup Hombli Smart Water Controller

1. Login at [Tuya IoT Platform](https://iot.tuya.com/)
1. Open your created project: **Cloud** (left bar) - **Open project**
1. Open **Devices** tab, select a random device and choose **Debug Device**
1. Select the Hombli Smart Water Controller (not the Gateway!!) in the left pane
1. Open **Device Debugging** tab and check if you see any information in **Standard Instuction Set** in the right pane
1. When there is no information change to **DP instruction mode** in **Product Details** https://iot.tuya.com/cloud/setMode?id=p170422359011955aj7s&pid=**<device-id>**
1. In **Configure Control Instruction Mode** select change the instruction mode from **Standard Instruction** to **DP Instruction**
1. Repeat the steps in 3., 4. and 5. - you shoud see now information under **Standard Instruction Set**

### Setup custom repository in HACS

Open your Home Assistant instance and add a custom repository [Home Assistant Community Store (HACS)](https://hacs.xyz/docs/faq/custom_repositories/)
![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store](https://my.home-assistant.io/badges/hacs_repository.svg)

### Setup integration in Home Assistant

After installing, you can easily configure your devices using the Integrations configuration UI. Go to Settings / Devices & Services and press the Add Integration button, or click the shortcut button below (requires My Homeassistant configured).

![Add Integration to your Home Assistant instance](https://my.home-assistant.io/badges/config_flow_start.svg)
