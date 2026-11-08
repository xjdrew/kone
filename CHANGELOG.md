# 2026/11/08

## Features

- Rename the routing workspace to Proxy rules across navigation, messages and documentation.
- Add explicit layered routing upgrades, with domain rules before IP rules and decisions bound to the actual dialed address.
- Keep Fake-IP domain ownership across restarts and profiles, with capacity visibility and an explicit fresh-pool migration for legacy configurations.
- Unify DNS and connection health in Overview with persistent attention records, retesting, combined port results and handling history.
- Add opt-in temporary outbound selection that respects manual rules, with proxy DNS recovery and one-click pinning as a permanent rule.

## Bugfixes

- Simplify Overview to one health table, ignore native DNS failures on working proxy routes, and choose rule outbounds inline while allowing paused/legacy Smart preferences.

- Collect repeated connection errors in timed notifications and a status-bar error history without disrupting page layout.
- Apply Comfortable density to typography, form spacing, controls and table rows.

- Accept domain/IP connection targets and proxy addresses without a port, defaulting to 80 while DNS retains port 53.
- Preserve domain identity for direct exceptions under global capture and stop stale or unrelated DNS evidence from choosing another target.

## Changes

- Combine Notifications, Diagnostics and Logs in one floating tabbed tool panel without resizing the main page.

- Clarify connection-health status, issue resolution and inline rule actions in the product and UI specifications.

# 2026/11/07

## Features

- Add Host and Gate DNS modes with system-upstream discovery, explicit public fallback warnings and a redesigned Resolvers page.
- Compare system DNS and KONE DNS by query name, including answers and Fake-IP policy results.
- Enable Linux capture through a native polkit authorization dialog while keeping management unprivileged.
- Recall up to 20 recent diagnostic targets, separate DNS queries from connection tests, and show total test time in result summaries.

- Choose a local private address or all IPv4 interfaces for remote management, use HTTP or HTTPS, and set a password as part of first-time enablement; HTTPS includes CA trust guidance.
- Rebuild the Web console around Traffic, Proxy rules and Outbounds workspaces, with contextual rule editing, keyboard commands and persistent diagnostics/log tools.
- Add editable direct-first and global-proxy policies with loop prevention and editable LAN direct defaults, country exceptions, IPv6 scope and explicit UDP fallback consent; existing profiles retain their intent.
- Check configured outbounds periodically in turn using their actual proxy protocol, with per-outbound targets and an off switch.
- Diagnose any domain or IP with optional presets, live per-outbound summaries and expandable details.
- Add offline English and Chinese interfaces, system-language detection and per-client language preferences, including desktop menus and translated operation summaries.

- Open the numeric loopback management address without a password while keeping remote access authenticated.
- Apply IPv4 and IPv6 CIDR rule changes live while preserving established connections.
- Automatically choose a non-conflicting IPv6 subnet for new management profiles on capable hosts, preserving existing settings.
- Group attention events and connection records by target while retaining individual connection details.
- Control the proxy with a switch beside live upload/download rates and show compact final-rule summaries.

## Bugfixes

- Enable Host DNS on Linux without systemd-resolved, preserving and restoring the original resolver file or WSL symlink.
- Accept port-free connection targets as TCP 80, unify diagnostic history controls and keep save feedback from covering actions.
- Allow default direct routing without configuring a proxy or confirming direct-only mode; removing proxy rules applies immediately.
- Explain startup blockers and their next steps, keep the enable action visible, and allow readiness checks without starting capture.
- Allow private-network proxy rules while keeping local hosts and KONE’s own proxy/DNS transports outside recursive capture; preserve deleted LAN defaults across restarts.

- Keep graph labels readable on narrow screens and inspect Windows route changes without launching console commands.

- Preserve the helper's final cleanup logs when stopping capture.

## Changes

- Document the two-base-mode design with shared custom rules, routing and cache limitations, proxy-tool comparisons, and Windows/macOS application-rule feasibility.
- Document proposals for fixed rule layers, consistent dial targets, durable Fake-IP ownership, and optional Smart suggestions for both proxy and direct routing.
- Replace pairing codes with management-password sign-in and revocable remote sessions.
- Reduce contributor wait time for automated checks across supported platforms.
- Define Web console design rules around traffic, proxy rules and outbounds workspaces, contextual tools, dense layouts and efficient keyboard workflows.
- Use clearer proxy terminology throughout the console, tray and guides.
- Consolidate user and developer guides, replace historical notes with current instructions, and define product and Web requirements for future redesigns, including transparent routing, performance and payload privacy goals.

# 2026/11/01

## Features

- Open management on desktop launch, explain tray access and offer quiet startup with `-no-browser`.
- Filter runtime logs by time and browse history in a compact diagnostics table with pagination.
- Create rules with type-specific inputs and country choices, and see the matched rule in routing simulations.
- Diagnose UDP paths with validated DNS responses through direct, SOCKS5 and Shadowsocks outbounds.
- Guide Windows system DNS through KONE, with explicit recovery after abnormal exit.
- Support optional IPv6 capture on macOS.
- Select DB-IP, IPinfo Lite or MaxMind GeoLite2 country databases, including IPv6 GeoIP rules.
- Configure proxy protocols, addresses and authentication in compact forms and follow live connection checks with measured latency.
- Include system, gVisor and mixed stacks in every build, selected at runtime with system as the default.
- Record management startup, capture lifecycle and network helper progress in runtime logs.
- Change the management password and reset all settings while capture is paused from Settings.
- Require a management password on first use and password authentication on later logins.
- Guide first-time capture setup with ready-to-use defaults and explicit direct-only confirmation.
- Show configuration as status lists with focused editors, outbound connection tests and live rule/outbound updates.
- Protect TUN and other restart-required settings while capture is running.
- Add application and tray icons, terminal-free Windows/macOS desktop launch, and a separate console CLI.
- View filtered, redacted recent runtime logs in Diagnostics.
- Show defaults, options and examples with `-h` or `--help` on every daily just command.
- Open a local management interface without preparing a configuration file.
- Manage capture, outbounds, rules and DNS through a responsive desktop and mobile interface.
- Inspect live TCP/UDP traffic, failed connections and Sankey paths.
- Compare connectivity, simulate routing and save precise rules without replaying application requests.
- Save, import, export and restore settings with version conflict checks and credential redaction.
- Enable authenticated HTTPS LAN access with expiring pairing codes and revocable sessions.
- Support SOCKS5 UDP and Shadowsocks AEAD TCP/UDP outbounds.
- Support DNS over TCP, truncated-response retry, private suffix resolvers and bounded query history.
- Import verified GeoIP datasets and restore the previous version.
- Update built-in IPv4 country data to DB-IP Country Lite October 2026.
- Show verified local process ownership where the operating system allows it.
- Support optional IPv6 capture on Linux and Windows.
- Request a separate Windows/macOS network helper when capture needs administrator permission.
- Control capture and open diagnostics from the Windows system tray or macOS menu bar.
- Support expiring domain rules and disabled proxy outbounds.
- Guide system DNS through KONE on supported Linux and macOS systems.
- Preserve discovered private DNS scopes and show resolver context.
- Build installable packages and verified development releases for successful master commits.

## Bugfixes

- Explain incompatible saved password files in the desktop startup dialog and show how to reset authentication while keeping other settings.
- Keep Windows background DNS and network checks from flashing console windows on startup or during capture.
- Keep Settings menu links responsive while live status updates refresh their summaries.
- Preserve log filters, expanded fields and reading position during automatic updates.
- Show real outbound connection failures in runtime logs at the default log level.
- Prevent intercepted domains from bypassing their proxy rules through real IPv6 DNS answers when IPv6 capture is disabled.
- Reject invalid diagnostic addresses and consistently enforce probe limits.
- Keep unsaved proxy edits when enabling direct-only capture.
- Preserve editor drafts and return navigation during browser history changes and configuration refreshes.
- Keep Windows packaging from changing tracked frontend files solely because of line endings.
- Keep gateway capture stable when using the gVisor stack.
- Hide management navigation and controls until login succeeds, including during initial loading and after logout.
- Automatically clear safe capture leftovers on startup and show stopped capture status accurately.
- Keep signed-out sessions closed and resume first-time password setup after refreshing the page.
- Show capture failures from the tray and open diagnostics without closing management.
- Keep management usable when capture telemetry is temporarily unavailable instead of reporting a lost connection.
- Build Windows installation packages without installing PowerShell 7.
- Keep management available while capture is paused or fails to start.
- Preserve active Fake-IP mappings and prevent private DNS fallback to public resolvers.
- Pause capture when the physical network context changes.
- Refresh expired DNS addresses and CNAME routing decisions without changing active connections.
- Offer the last valid settings for repair when the saved profile is damaged.
- Honor explicit direct domain rules before later default policies.
- Preserve existing macOS routes when capture startup fails.
- Mark retained traffic as historical after capture stops.
- Preserve the observed protocol and port when drafting a precise rule.
- Preserve both proxy username and password when editing credentials.

## Changes

- Reduce management password hashing cost; exit KONE and move the old `auth.json` aside to set a new password, while retaining `settings.json` and other configuration.
- Keep the infrequently used log time filter behind one control and omit routine network-refresh command logs.
- Compact the outbound list, show built-in targets first and display saved-rule reference counts.
- Keep FINAL in a fixed group below ordinary rules and edit its fallback outbound separately.
- Keep editors focused on save and cancel, validate automatically, and reveal advanced settings and tests only when needed.
- Derive versions from cumulative feature and bugfix changes, with master prereleases and tag-triggered stable releases.
- Publish Windows ZIP, macOS PKG and Linux DEB for amd64/arm64; keep ARMv7 gateway builds as an explicit option.
- Start capture without a technical preflight confirmation screen; show execution details in runtime logs.
- Add matching action icons and clearer grouping to the Windows tray menu.
- Organize Settings into grouped menus and dedicated subpages, with About first and reset/logout at the bottom.
- Update console status automatically and keep account and maintenance controls in Settings.
- Remove legacy HTTP management and `general.manager-addr`; use the password-protected Web console.
- Run Windows stack checks in parallel while preserving platform and release validation.
- Simplify setup, development, checks, builds and packaging into a few just commands.
- Keep local packaging limited to creating files without running or installing the program.

# 2026/10/31

## Features

- Support Windows UAC elevation on startup.
- Use Wintun on Windows without a separate TAP installation.
- Support optional full IPv4 traffic takeover on Linux and Raspberry Pi gateways.
- Add system and mixed network-stack options.
- Add named proxy outbounds and built-in direct/reject policies.
- Use system DNS by default, with optional settings in `[dns]`.
- Reject unsupported proxy UDP by default and allow explicitly configured fallback.
- Add configuration checks, structured logs and clearer startup errors.

## Bugfixes

- Fix crashes when TUN initialization fails.
- Fix occasional failures during concurrent shutdown.
- Fix incomplete network cleanup after startup failures or shutdown.
- Fix stale routing policies after rule reload.

## Changes

- Switch configuration to TOML; migrate INI files and remove obsolete relay settings.
- Improve configuration, Windows and gateway documentation.
- Change the project license to GPL-3.0-or-later.

# 2023/12/26

## Features

- Support Windows 10.
- Support rule reload through the management interface.
- Use system DNS by default.
- Adopt Surge-style configuration.
