# Moflin BLE command protocol

## 1. Packet header byte (first byte of every 8-byte-block packet)

From `MoflinV1CommandHandler._processData` (the notify
dispatcher) calls a header getter, then dispatches on the value:

| Header value | Meaning | Where handled |
|---|---|---|
| `0x80` (128) | **MTUReadResponse** | outer branch @ `0x93065c` (logs `_processData/Missing elements headerMTUReadResponse`) |
| `0x81` (129) | **EncryptionKeyGenerateResponse** | outer branch @ `0x930730` (logs `…headerEncryptionKeyGenerateResponse`) |
| `0x40–0x7F` (`b & 0xC0 == 0x40`) | **Command** (normal command/response traffic) | bitmask test @ `0x930814`, then `…headerCommand` |
| `0x4F` | checked explicitly @ `0x930844` (specific Command subcase / type selector) | |

The handshake order before encrypted traffic: **MTURead → EncryptionKeyGenerate
→ Command**. The key-exchange packet is the `EncryptionKeyGenerate` pair — this
is where the 16-byte seed for `__c00__` (see UPDATER_ANALYSIS §5/§6) is agreed,
so capture/replay the *first two* exchanges of a session to obtain the seed.

## 2. Receive-side command/response ID table (`_processData` inner switch)

The inner switch (cascade root @ `0x930924`, binary-search on a 64-bit value)
dispatches the command/notify value. Verified by simulating the cascade:

| Value | Meaning | Evidence (handler @, log string pool idx) |
|---|---|---|
| 0, 1 | data notification (generic value dispatch w/ getter) | → `0x9313e4` (virtual getter on value) |
| 2 | **read/data response** — forwarded to the `Receive ID:0x` processor (`0x3fcf58`) | `0x930974`: `cmp r0,#4` (Smi 2) → virtual 3-arg call → `0x3fcf58` |
| 3–5 | data response family | `0x930a0c` |
| 6 | data response family (own branch) | `0x9309f0` |
| 7 | **OperationFailed** (error) | `0x930a14`/`0x930b0c` logs pool 14786 |
| 8 | **InvalidOpCode** (error) | `0x930b0c`… pool 14788 |
| 9 | **InvalidSequence** (error) | `0x930c00` pool 14790 |
| 10 | **InvalidParameterLength** (error) | `0x930cd0` pool 14792 |
| 11 | **InvalidParameter** (error) | `0x930da0` pool 14794 |
| 12 | **InvalidMode** (error) | `0x930eb4`-tree pool 14796 |
| 13 | **Busy** (error; `_sendCommandRetry` retries on this) | pool 14797 |
| 14 | **NotAuthenticated** (error) | `0x93105c` pool 14799 |
| 15, 16 | command carrying an **errorCode** parameter (`commandID: X: errorCode: Y` log) | `0x9313e0` (getter + pool 14806 `': errorCode: '`) |
| 17 | **LowBattery** (error) | `0x931160` pool 14801 |
| 18 | **LowTemperature** (error) | `0x931230` pool 14803 |
| ≥19 | **HighTemperature / UnknownError** (error) | `0x931300`-tree pools 14805/14808; default logs `Unknown CommandID` (pool 14809) |

Error strings live at pool entries 14786–14809 (`MoflinV1CommandHandler._processData(<Name>): `).

## 3. Send-side command flow (function map)

```
public API methods (14 call sites of 0x8c132c "sendCommand(id, params)")
  └─ 0x8c132c  sendCommand(commandId, params)        [reads result via 0x310664,
  │             logs 'Read command result:']            virtual dispatch 0x8c140c]
  ├─ 0x92b0d0  forwarder (7 callers, e.g. 0x6c1988 — connection/scan code)
  ├─ 0x92cdc8  executeDataSend send (FW data packets, slot 3)
  ├─ 0x92f264  startCommunication (sends slot 4; logs 'Write start communication
  │             command send completed')
  └─ 0x344524  log wrapper: builds 'command header: H, ID: I, params: P'
       └─ 0x8c148c  async wrapper (timeout/future plumbing)
            └─ 0x8c17a8  _sendCommandRetry (logs 0x8c187c; retries on Busy)
                 └─ 0x8c1974  _sendCommand  ← logs 'Send ID: 0x<hi><lo>'
                      └─ 0x348d20  id→bytes (byte-swap: hi-byte first)
                      └─ 0x348c50 → 0x3487f4  packet build + write queue
```

**Command IDs are 16-bit values** — `_sendCommand` prints them as exactly two
hex bytes (`hex(byte1) + hex(byte0)`, built @ `0x8c1b28–0x8c1bd4`), and the
response parser dispatches on the same 16-bit space.

## 4. Where the send-command ID values live (the one remaining gap)

Send command IDs are **Dart enum constants** (`MoflinModeCommandType`,
`MoflinFirmwareType`, `MoflinVersionType`, …).

The enum member *names* were:
`MoflinModeCommandType`, `MoflinFirmwareType`, `MoflinVersionType`,
`MoflinLogDataType`, `MoflinStimulusType`, `MoflinModeType`,
`MoflinPowerStatus`, `MoflinChargeStatus`, `MoflinSoftwareStatus`,
`MoflinDeviceCommandErrorType`, `MoflinRegistrationErrorType`,
`MoflinConnectAndAuthErrorType`, `MoflinDeviceConnectionErrorType`, …
plus member-name strings present in the snapshot: `startScan`, `stopScan`,
`scanCancel`, `scanTimeout`, `wakeUp`, `turnOn/turningOn/turningOff`,
`postureFlat`, `postureHalfOpened`, `deepSleep`, `powerSave1/2`,
`houseOut`, `notChargingInHouse/OutHouse`, `chargeError`, `fullyCharged`,
`bigSound`, `hHeadTouch`, `hLrswing`, `dakkoLrswing`, `kubiNade`,
`vDakkoBodyTouch`, `vDakkoHeadTouch`, `sameKimagure`, `logTransfer`,
`backupLog`, `behaviorData/behaviorVersion/fwVersion`, `invalidMode`,
`invalidOpCode`, `invalidParameter`, `invalidSequence`, `invalidTarget`,
`unexpectedData`, `gotName/expectedName/newName/originalName`, …
