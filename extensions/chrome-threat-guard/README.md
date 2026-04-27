# Threat Guard Chrome/Edge Extension

This extension pairs with the Threat Guard desktop app and gives the password manager a real web save/autofill flow.

## Load it in Chrome or Edge

1. Open `chrome://extensions` or `edge://extensions`
2. Turn on **Developer mode**
3. Click **Load unpacked**
4. Select the `extensions/chrome-threat-guard` folder from this repo
5. Open Threat Guard -> `Password Manager`
6. Copy the pair code shown in the `Browser Autofill Bridge` card
7. Click the extension icon and paste the code into the popup

## What it does

- Detects password-form submissions in Chrome and Edge
- Asks whether you want to save the credential to Threat Guard
- Pulls matching credentials from Threat Guard on later visits and autofills them
- Stores the paired browser token in the extension, while the real credentials stay in the Threat Guard desktop vault

## Current v1 scope

- Works for websites in Chromium browsers through the included extension
- Uses the Threat Guard localhost bridge at `http://127.0.0.1:38913`
- Saves into the desktop app's encrypted Windows vault
- Supports many multi-step logins when the username and password flow stays on the same origin, such as `accounts.google.com`

## Not in this first version

- Native desktop application login capture
- Firefox support
- Account picker UI when several saved accounts match the same site
