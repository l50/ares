<!-- DOCSIBLE START -->
<!-- DOCSIBLE START -->
# redis

## Description

Redis server for Ares worker message broker

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `redis_bind_address` | str | <code>127.0.0.1</code> | No description |
| `redis_port` | int | <code>6379</code> | No description |
| `redis_maxmemory` | str | <code>256mb</code> | No description |
| `redis_maxmemory_policy` | str | <code>allkeys-lru</code> | No description |
| `redis_install_ares_worker_unit` | bool | <code>True</code> | No description |
| `redis_ares_worker_binary` | str | <code>/usr/local/bin/ares</code> | No description |
| `redis_ares_log_dir` | str | <code>/var/log/ares</code> | No description |
| `redis_ares_config_dir` | str | <code>/etc/ares</code> | No description |
| `redis_ares_worker_memory_high` | str | <code>1500M</code> | No description |
| `redis_ares_worker_memory_max` | str | <code>2G</code> | No description |
| `redis_ares_worker_tasks_max` | int | <code>256</code> | No description |
| `redis_ares_slice_memory_high` | str | <code>10G</code> | No description |
| `redis_ares_slice_memory_max` | str | <code>12G</code> | No description |
| `redis_ares_slice_tasks_max` | int | <code>8192</code> | No description |
| `redis_ares_otel_resource_attributes` | str | <code>deployment.environment=staging,attack.team=red</code> | No description |
| `redis_ares_worker_roles` | list | <code>&#91;&#93;</code> | No description |
| `redis_ares_worker_roles.0` | str | <code>recon</code> | No description |
| `redis_ares_worker_roles.1` | str | <code>credential_access</code> | No description |
| `redis_ares_worker_roles.2` | str | <code>cracker</code> | No description |
| `redis_ares_worker_roles.3` | str | <code>acl</code> | No description |
| `redis_ares_worker_roles.4` | str | <code>privesc</code> | No description |
| `redis_ares_worker_roles.5` | str | <code>lateral</code> | No description |
| `redis_ares_worker_roles.6` | str | <code>coercion</code> | No description |
| `redis_verify_install` | bool | <code>False</code> | No description |

## Tasks

### linux.yml


- **Install Redis server** (ansible.builtin.apt)
- **Configure Redis bind address** (ansible.builtin.lineinfile)
- **Configure Redis port** (ansible.builtin.lineinfile)
- **Configure Redis maxmemory** (ansible.builtin.lineinfile)
- **Configure Redis maxmemory-policy** (ansible.builtin.lineinfile)
- **Enable and start Redis** (ansible.builtin.systemd)
- **Create Ares directories** (ansible.builtin.file)
- **Stat legacy ares-worker@ template unit** (ansible.builtin.stat)
- **Disable + stop legacy ares-worker@ instances** (ansible.builtin.systemd) - Conditional
- **Remove legacy ares-worker@ template unit** (ansible.builtin.file) - Conditional
- **Install Ares system slice (global fleet cgroup cap)** (ansible.builtin.template) - Conditional
- **Install Ares worker systemd template unit** (ansible.builtin.template) - Conditional
- **Enable and start Ares worker instances** (ansible.builtin.systemd) - Conditional
- **Verify Redis is responding** (ansible.builtin.command) - Conditional
- **Display Redis verification** (ansible.builtin.debug) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - redis
```

## Author Information

- **Author**: Dreadnode
- **Company**: dreadnode
- **License**: MIT

## Platforms


- Ubuntu: all
- Debian: all
- Kali: all
<!-- DOCSIBLE END -->
<!-- DOCSIBLE END -->
