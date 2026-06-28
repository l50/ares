#!/bin/bash
# ares-golden-image build instance bootstrap (cloud-init user-data).
#
# Why this exists (and not pure warpgate/Image Builder): the NVIDIA driver on the
# Kali cloud AMI must be installed against a kernel whose headers are in-repo
# (the running kernel's aren't), and the box MUST reboot into that kernel before
# GPU compute works — otherwise the DKMS module is built while running the old
# kernel and hashcat enumerates the T4 but hangs on kernel build. EC2 Image
# Builder cannot reboot the Kali builder mid-build (its SSM orchestration doesn't
# rejoin after the reboot -> CANCELLED). So we do it on a plain instance that
# handles its own reboot via a systemd oneshot, then snapshot.
#
# Phase 1 (first boot): SSM agent + aws cli + kernel/headers/driver + ansible +
#   collection, install a one-shot phase-2 unit, then reboot.
# Phase 2 (after reboot, driver loaded on target kernel): run goad_attack_box.yml
#   with the driver/cuda steps disabled, then signal done via S3.
set -xuo pipefail
exec >/var/log/ares-golden-build.log 2>&1
export DEBIAN_FRONTEND=noninteractive
BUCKET=warpgate-staging-898493401173-use1
PFX=s3://$BUCKET/ares-golden-build

apt-get update
# grub2-common provides update-grub, which goad_attack_box.yml's THP-disable task
# needs (not present on the minimal Kali cloud base).
apt-get install -y curl unzip git pipx ca-certificates grub2-common

# SSM agent (not preinstalled on Kali) + AWS CLI v2 (no awscli apt pkg on Kali)
curl -fsSL https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb -o /tmp/ssm.deb
dpkg -i /tmp/ssm.deb || apt-get install -f -y
systemctl enable --now amazon-ssm-agent
curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/a.zip
unzip -q -o /tmp/a.zip -d /tmp && /tmp/aws/install --update
AWS=/usr/local/bin/aws

# Kernel + headers (in sync, in-repo) + NVIDIA driver WITH recommends (nvidia-smi
# + compute test stack) + clinfo. DKMS builds the module for the installed kernel;
# the reboot below boots into it so the module is loaded/validated.
apt-get install -y linux-image-cloud-amd64 linux-headers-cloud-amd64 dkms
apt-get install -y nvidia-driver nvidia-opencl-icd clinfo firmware-misc-nonfree
dkms status

# ansible + the nimbus_range collection (for phase 2)
pipx install --force ansible-core
COLL=/root/.ansible/collections/ansible_collections/dreadnode/nimbus_range
mkdir -p "$COLL"
$AWS s3 cp $PFX/ares-ansible.tar.gz /tmp/ares.tgz --region us-east-1
tar -xzf /tmp/ares.tgz -C "$COLL"
/root/.local/bin/ansible-galaxy collection install -r "$COLL/requirements.yml" --force

# Phase 2 one-shot: runs after the reboot, when the driver is live on the target kernel.
cat >/usr/local/bin/ares-phase2.sh <<'P2'
#!/bin/bash
set -xuo pipefail
exec >> /var/log/ares-golden-build.log 2>&1
# Full PATH incl. sbin dirs — dpkg/apt need ldconfig + start-stop-daemon (in /usr/sbin,/sbin).
export HOME=/root PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BUCKET=warpgate-staging-898493401173-use1; PFX=s3://$BUCKET/ares-golden-build
COLL=/root/.ansible/collections/ansible_collections/dreadnode/nimbus_range
AWS=/usr/local/bin/aws
nvidia-smi --query-gpu=name,driver_version --format=csv,noheader || true
ANSIBLE_REMOTE_TMP=/tmp/at ansible-playbook "$COLL/playbooks/ares/goad_attack_box.yml" \
  -i localhost, -c local -e ansible_shell_executable=/bin/bash -e ansible_python_interpreter=/usr/bin/python3 \
  -e cracking_tools_gpu_support=true -e cracking_tools_nvidia_opencl_icd=true \
  -e cracking_tools_install_nvidia_driver=false -e cracking_tools_install_cuda_toolkit=false \
  -e cracking_tools_hashcat_from_source=false
RC=$?
# clean apt caches before snapshot
apt-get clean; rm -rf /var/lib/apt/lists/* /tmp/ansible* 2>/dev/null || true
$AWS s3 cp /var/log/ares-golden-build.log $PFX/build.log --region us-east-1 || true
echo "$RC" > /tmp/rc && $AWS s3 cp /tmp/rc $PFX/PHASE2_DONE --region us-east-1
systemctl disable ares-phase2.service
P2
chmod +x /usr/local/bin/ares-phase2.sh

cat >/etc/systemd/system/ares-phase2.service <<'UNIT'
[Unit]
Description=ares golden phase2 (tools install + done signal)
After=network-online.target amazon-ssm-agent.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ares-phase2.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ares-phase2.service

$AWS s3 cp /var/log/ares-golden-build.log $PFX/build.log --region us-east-1 || true
echo "phase1 done; rebooting into target kernel"
reboot
