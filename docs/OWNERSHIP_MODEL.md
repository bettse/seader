# Ownership Model

This document is a contract. It is normative.

Code touching HF, UHF, SAM, worker lifecycle, `.fal` plugins, `Nfc`, or `NfcDevice` must follow this model exactly.

## Lifetimes

- App lifetime: objects allocated in `seader_alloc()` and released in `seader_free()`.
- Mode runtime lifetime: the currently active RF mode tracked by `SeaderModeRuntime`.
- HF session lifetime: the loaded HF plugin runtime tracked by `SeaderHfSessionState`.
- Read conversation lifetime: a single card detect/conversation attempt.

## Owners

### App-lifetime host owner: `Seader`

The host owns and configures:

- `Nfc`
- `NfcDevice`
- UART / CCID / SAM transport
- view / scene infrastructure
- shared credential and result storage
- `SeaderModeRuntime`

Rules:

- Host-owned objects must be configured once by the host owner.
- Session teardown must not mutate host callback wiring.
- `nfc_device_set_loading_callback()` is host-only and must never be called with `NULL`.

### HF session owner: worker teardown/startup path

The worker owns all live HF runtime:

- HF plugin manager
- HF plugin entry point
- HF plugin context
- host-owned HF pollers, if any
- HF worker queue / stage reset
- `SeaderHfSessionState`

Rules:

- Only worker startup may create or activate an HF session.
- Only worker teardown may stop, free, and unload an HF session.
- Scenes must not mutate HF pollers, worker queue state, or HF plugin pointers.

### Scene owner

Scenes own presentation only:

- popup text and icons
- blink state
- scene transitions
- read-abort UI cleanup

Rules:

- Scenes may request teardown.
- Scenes must not stop/free pollers, unload the HF plugin, or reset the worker queue/stage.

### SAM card-state owner

SAM active-card state is owned by the read lifecycle.

Rules:

- Successful reads must clear active-card state after the final result is copied.
- Aborted reads after detect/conversation must clear active-card state before leaving the flow.
- Success, More, Parse, and Save scenes must not own SAM card cleanup.

## State invariants

| `mode_runtime` | `hf_session_state` | Allowed HF pointers |
| --- | --- | --- |
| `None` | `Unloaded` | all HF runtime pointers must be `NULL` |
| `HF` | `Loaded` | plugin manager, plugin EP, plugin ctx may be non-`NULL`; pollers may be `NULL` |
| `HF` | `Active` | plugin manager, plugin EP, plugin ctx must be non-`NULL`; active pollers may be non-`NULL` |
| `HF` | `TearingDown` | teardown owns all pointer mutation; no scene code may touch HF runtime |
| `UHF` | `Unloaded` | all HF runtime pointers must be `NULL`; UHF maintenance/probe flow owns mode runtime |

Invalid combinations are bugs:

- `mode_runtime == HF` with `hf_session_state == Unloaded`
- `mode_runtime == None` with live HF plugin pointers
- `mode_runtime == UHF` with any live HF runtime pointer
- `hf_session_state == Active` with `plugin_hf == NULL` or `hf_plugin_ctx == NULL`

## Required ordering

### HF startup

Legal startup paths:

1. Cold acquire:
   - verify `mode_runtime == None`
   - verify `hf_session_state == Unloaded`
   - load `plugin_hf.fal`
   - resolve plugin entry point
   - allocate plugin context
   - set `hf_session_state = Loaded`
   - set `mode_runtime = HF`
   - start read and transition to `Active`
2. Fast-path re-acquire:
   - allowed only when the existing HF runtime is already coherent
   - preserve the existing `Loaded` or `Active` state
   - do not unload/reload the plugin

Any partial pointer/state combination must first normalize to `Unloaded`.

### HF teardown

1. Set `hf_session_state = TearingDown`
2. Stop plugin-owned pollers via `plugin_hf->stop()`
3. Stop/free host-owned HF pollers
4. Free plugin context
5. Unload plugin manager
6. Null all HF runtime pointers
7. Reset HF worker queue/stage
8. Set `hf_session_state = Unloaded`
9. Set `mode_runtime = None`

The blocking fallback teardown path must use the same state machine and ordering.
This order must be implemented in one worker-owned release primitive and nowhere else.

## Forbidden actions

- Calling `nfc_device_set_loading_callback(..., NULL, ...)`
- Scene code calling `seader_worker_reset_poller_session()`
- Scene code calling `seader_worker_cancel_poller_session()` as part of teardown
- Scene code freeing or unloading HF runtime
- Reusing a stopped HF plugin context as if it were a fresh session
- Starting UHF while HF session state is not `Unloaded`
- Starting HF while `mode_runtime == UHF`

## UHF runtime

`SeaderModeRuntimeUHF` is active only while the SAM maintenance/SNMP probe flow is active.

Rules:

- UHF runtime must be entered when the probe starts.
- UHF runtime must be cleared when the probe finishes.
- While UHF runtime is active, HF acquire must be rejected.
- UHF runtime must not coexist with any live HF runtime pointer.

## Plugin boundary

`hf_interface_fal/` and `wiegand_interface_fal/` are part of this repository. They are not submodules.

Rules:

- HF and Wiegand plugin sources must remain in-tree and follow this contract.
- The host/plugin boundary is narrow:
  - host owns orchestration, SAM transport, UI routing, and lifetime
  - each plugin owns only its protocol-specific execution
- Plugins must not directly own scene transitions or global app teardown.

## Change checklist

Before merging a change that touches HF/UHF/session code, confirm:

- every new object has one declared lifetime
- every new object has one mutation owner
- every new object has one release path
- no scene code mutates live HF runtime
- no teardown path mutates app-lifetime callback wiring
- all state-table invariants still hold
- `OWNERSHIP_MODEL.md` changed in the same patch as any lifetime/order/state-machine change
- this document still matches the implementation
