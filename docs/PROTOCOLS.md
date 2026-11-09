# Protocol support and limits

Remote embeds its transports. Supported negotiation and optional channels vary
by server; this table describes implemented contracts and remaining limitations.

| Protocol / baseline | Integrated contracts | Remaining integrations / qualification limits |
|---|---|---|
| VNC, RFB 3.8 and VeNCrypt 0.2 | Raw, CopyRect, ZRLE persistent zlib/tile palettes/RLE, DesktopSize, LastRect; classic VNC challenge; verified X509None/X509Vnc TLS; pointer/wheel/keys, clipboard typing and bidirectional bounded classic/extended UTF-8 text sharing under capture/session policy | No Tight/JPEG/H.264 encoding, extended desktop layout/multi-monitor, cursor pseudo-encoding, rich/file clipboard or audio extension. These extensions are not required for RFB 3.8 interoperability. No anonymous TLS or certificate bypass. |
| RDP, IronRDP session 0.13 / MS-RDPEA / MS-RDPEDISP | TLS, NTLM NLA, 32-bit graphics/reactivation, input and CLIPRDR Unicode text; RDPSND PCM16 mono/stereo 8–192 kHz with advertised-index preservation, legacy split Wave/Wave2/training/confirm; optional DisplayControl with an interactive-session resize-to-viewer toggle | No gateway, Kerberos/KDC, RemoteApp, drive/printer/smartcard/USB redirection, microphone or AVC graphics pipeline. PCM is an interoperable format subset; compressed RDPSND formats are not advertised. Windows hardware/server qualification remains separate. |
| SPICE, upstream spice-client-glib 0.42+ / spice-protocol | Main/display/input plus upstream SpiceAudio playback/recording; opt-in agent monitor configuration with a live resize-to-viewer toggle; verified TLS for non-loopback; bounded framebuffer publication and guest-agent UTF-8 clipboard | One local SPICE session and primary display; no horizontal wheel events, cursor channel, separate microphone controls, USB, smartcard, WebDAV, GL scanout or migration. Monitor mode activation also requires a functioning guest agent and desktop display-settings service. Audio channels and local device initialization follow upstream SpiceAudio behavior; the Audio setting disables audio channels, with no separate microphone policy. |
| RustDesk 1.5.1, hbbs/hbbr 1.1.16 | Direct addresses and signed ID discovery, authenticated relay routing, KXv1 directional NaCl, per-host permission updates (interactive sessions close on keyboard revocation); VP8/VP9/H.264/HEVC/AV1 capability checks; Opus playback and bounded plain/zstd UTF-8 clipboard under host permission; keyboard/pointer and immutable view-only | Relay is intentionally selected for ID sessions; no direct UDP hole-punch optimization, multi-display composition, file transfer, address book/account/Pro features, recording or mobile-specific permissions. Custom rendezvous roots must be supplied explicitly. Keep the viewer focused until the copy-completion notice before switching windows; deferred native clipboard offers for late results are not implemented. Internet/default-service availability is not exercised by local QA. |
| Moonlight Common-C 3b6ee9d / Sunshine v2026.914.233613; Moonlight Qt 6.2.0 comparison | PIN/client/server certificate pairing, encrypted control/video/audio, H.264/HEVC/AV1 SDR decoder negotiation, Opus playback; explicit resume consent including launch race; UTF-8 fallback; SDL gamepad state/hotplug/neutralization and bounded rumble | No clipboard synchronization: the explicit Type clipboard text action forwards input only; Unicode depends on the host/application input method. No HDR/10-bit pipeline, microphone, controller motion/touch/battery/LED/trigger effects, touch/pen, surround-device routing or host app browser. One local stream. Physical force feedback and hardware codec paths are not qualified by the virtual controller/software-decoder fixture. Synchronous SDK stop/Drop keeps the singleton claim until native workers retire. |

All transports retain profile UUID and session-generation routing, cancelled-dial
fences, close debt, bounded queues/frame allocations and stale-result rejection.
Desktop transports preserve held-key/button release and immutable view-only defaults. Resizing targets the
profile session, not a process-global desktop. Audio never opens a microphone.
Gamepad forwarding requires an explicit profile option and the current capture
lease; focus loss, emergency release and disconnect neutralize forwarded state.
Upload destinations retain session/directory revalidation and chooser custody.
Software streaming decoders cap video at 3840×2160. Shared framebuffer admission
allows at most 8,388,608 pixels / 32 MiB RGBA and an 8192-pixel edge. Dynamic
resize requests stay within 200–3840 × 200–2160 pixels.

File transfer is handled by Files. File drops into desktop viewers are unavailable. Protocol descriptions
do not establish interoperability with every server or optional extension.

SSH tunnels are available for VNC, RDP, SPICE and RustDesk (including ID discovery
and relay connections). OpenSSH authenticates using a selected identity file or
agent/default keys and verifies existing known-host trust. Standalone SSH/SFTP
connections are not offered; legacy rows stay on disk, and imports containing
SSH profiles are refused with an explanation. TLS keeps the original desktop
hostname through the tunnel. A failed SSH route never falls back to direct access.
Optional local, remote and dynamic TCP forwarding rules share the route's lifetime.
Moonlight requires UDP and therefore needs a VPN rather than ordinary SSH forwarding.

Primary contracts and releases:

- [RFB protocol and extensions](https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst)
- [Microsoft RDPEA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpea/)
  and [RDPEDISP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/)
- [IronRDP releases](https://github.com/Devolutions/IronRDP/releases)
- [SPICE upstream source](https://gitlab.freedesktop.org/spice/spice-gtk)
- [RustDesk 1.5.1](https://github.com/rustdesk/rustdesk/releases/tag/1.5.1),
  [rendezvous schema](https://github.com/rustdesk/hbb_common/blob/master/protos/rendezvous.proto),
  [server releases](https://github.com/rustdesk/rustdesk-server/releases)
- [Moonlight Common-C](https://github.com/moonlight-stream/moonlight-common-c/commit/3b6ee9d916b0b1a7071fb9233e46089a59585bc7),
  [Qt releases](https://github.com/moonlight-stream/moonlight-qt/releases),
  [Sunshine releases](https://github.com/LizardByte/Sunshine/releases)
- [OpenSSH release notes](https://www.openssh.com/releasenotes.html)

Passing local fixtures does not qualify every server, device or extension.
