# Changelog

All notable changes to Graph.EasyPIM are documented here in reverse chronological order.

> ℹ️ This changelog was reconstructed from the Git history available in this repository. The earliest available commit already contains version `0.0.16`, so changes from earlier versions are not represented here.

## [0.0.21] - 2026-09-24

### Added

- Added copy/pasteable TUI selection tips to `Enable-PIMRole`, `Enable-PIMGroup`, `Disable-PIMRole`, and `Disable-PIMGroup`.
  - `Enable-*` tip cmdlets retain explicitly supplied activation and Graph connection parameters, and generate direct `-RoleName` or `-GroupName` selections.
  - `Disable-*` tip cmdlets generate direct selections. 
  - `Disable-PIMRole` and `Disable-PIMGroup` now support `-RoleName` and `-GroupName` respectively to bypass the TUI.

## [0.0.20] - 2026-09-23

### Changed

- Extended the eligible role and group cache from 8 hours to 7 days within the current PowerShell session.

### Fixed

- Restored the selection TUI for `Enable-PIMRole` and `Enable-PIMGroup` when no named selection parameter is supplied.

## [0.0.19] - 2026-09-23

### Added

- Added direct, non-TUI activation of eligible roles with `Enable-PIMRole -RoleName`.
  - An unsuffixed role name selects only a tenant-wide assignment.
  - Use `RoleName:Scope` to select an assignment at a specific administrative-unit or application scope.
- Added direct, non-TUI activation of eligible groups with `Enable-PIMGroup -GroupName`.
  - Use `GroupName:Member` or `GroupName:Owner` when both eligible assignment types exist.
  - An unsuffixed group name is accepted only when a single eligible assignment type exists.
- Added README examples for direct selection and `$PSDefaultParameterValues`.

### Changed

- Custom Graph `ClientId` and `TenantId` connection values are recognised when supplied through `$PSDefaultParameterValues`.

## [0.0.18] - 2026-09-23

### Added

- Added optional `-Duration` parameters to `Enable-PIMRole` and `Enable-PIMGroup`.
  - By default, activation still uses each item's maximum permitted duration.
  - A requested duration longer than an item's policy maximum is capped at that maximum and produces a warning.

Declared `Microsoft.Graph.Identity.SignIns` as a required dependency for role-management policy cmdlets.

### Changed

- Extended the in-session cache for eligible roles and associated policy data from 30 minutes to 8 hours.
- Documented the `-RefreshEligibleRoles` and `-RefreshEligibleGroups` force-refresh switches.

## [0.0.17] - 2026-09-09

### Changed

- Improved the ordering of Entra ID PIM role selections by role name and scope, placing tenant-wide assignments before scoped assignments for each role.
- Displayed group membership type in group selections.
- Added parameter sets that require `-TenantId` when `-ClientId` is supplied.

## [0.0.16] - 2026-06-15

### Changed

- Group membership type is displayed in selections.
- Roles are sorted.
- Custom-application parameter sets require `-TenantId` when `-ClientId` is supplied.

Changelog starts from this version.
