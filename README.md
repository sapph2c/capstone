# Capstone Project: Developing Evasive Malware with LLMs

## Setting up the Infrastructure

> [!NOTE]
> Ansible is required to setup the infrastructure. An installation guide can be found [here](https://docs.ansible.com/ansible/latest/installation_guide/index.html).

The first step is to request the following two deployments within RLES:

- Ubuntu 22.04 Desktop (any debian based system should work)
- Windows Server 2022

Once this is done, install Tailscale on both machines, as well as your host that you will be running Ansible from.

> [!NOTE]
> Download link for Tailscale can be found here: https://tailscale.com/download

After completing this step, fill the following variables of the Ansible role:

- windows_agent_ip
- linux_server_ip

Then from the root of the `ansible` directory, run the following command:

```
ansible-playbook -i inventory.ini main.yml
```

Once the playbook has completed, Jenkins server should be installed with necessary dependencies on the Linux host, and Jenkins agent should be installed on the Windows host.
