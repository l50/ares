<!-- DOCSIBLE START -->
<!-- DOCSIBLE START -->
# sysmon

## Description

Install and configure Sysinternals Sysmon on Windows hosts

## Requirements

- Ansible >= 2.13

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `sysmon_service_name` | str | <code>Sysmon64</code> | No description |
| `sysmon_install_dir` | str | <code>C:\Windows</code> | No description |
| `sysmon_binary_path` | str | <code>C:\Windows\Sysmon64.exe</code> | No description |
| `sysmon_config_path` | str | <code>C:\ProgramData\Sysmon\sysmonconfig.xml</code> | No description |
| `sysmon_windows_temp_dir` | str | <code>C:\Windows\Temp</code> | No description |
| `sysmon_installer_url` | str | <code>https://download.sysinternals.com/files/Sysmon.zip</code> | No description |
| `sysmon_config_url` | str | <code>https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml</code> | No description |
| `sysmon_enforce_config` | bool | <code>True</code> | No description |

## Tasks

### main.yml


- **Include OS-specific tasks** (ansible.builtin.include_tasks)

### windows.yml


- **Check if Sysmon service is already installed** (ansible.windows.win_service)
- **Ensure Sysmon config directory exists** (ansible.windows.win_file)
- **Fetch Sysmon config (SwiftOnSecurity)** (ansible.windows.win_get_url)
- **Download Sysmon installer** (ansible.windows.win_get_url) - Conditional
- **Extract Sysmon installer** (community.windows.win_unzip) - Conditional
- **Install Sysmon with config** (ansible.windows.win_command) - Conditional
- **Wait for Sysmon service to be running** (ansible.windows.win_service)
- **Clean up installer files** (ansible.windows.win_file) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - sysmon
```

## Author Information

- **Author**: Dreadnode
- **Company**: Dreadnode
- **License**: MIT

## Platforms


- Windows: all
<!-- DOCSIBLE END -->
<!-- DOCSIBLE END -->
