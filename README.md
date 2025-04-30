# Capstone Project: Developing Evasive Malware with LLMs

The objective of this project is to determine the practicality of using publicly available LLMs to modify malware samples to be more evasive, using sets of effective malware development strategies.

## Project Structure

```
capstone
├── Jenkinsfile
├── ansible/
│   ├── tasks/
│   └── vars/
└── scripts/
    ├── pipeline/
    └── src/
```

- `Jenkinsfile` holds the CI/CD pipeline configuration.
- `ansible` contains all the Ansible used to setup the Jenkins server & agent.
- `scripts` has the malware source code and the `pipeline` CLI tool used for calling the LLMs and running the malware callback tester.

## Getting Started:

Clone the repo:
```
git clone git@github.com:sapph2c/capstone.git
```

## Provision the Infrastructure

The first step is to request the following two deployments within RLES:

- Ubuntu 22.04 Desktop (any debian based system should work)
- Windows Server 2022

Once this is done, install Tailscale on both machines, as well as your host that you will be running Ansible from. Tailscale will enable us to configure the RLES machines from our personal computer, as well as access the Jenkins web interface from our host.

Download link for Tailscale can be found here: https://tailscale.com/download

For the Linux host, go to https://login.tailscale.com/admin/machines, click `Add Device` -> `Linux server` -> `Generate install script`, and then copy and run the script on the device.

## Setup Hosts for Ansible

> [!NOTE]
> Ansible is required to configure the infrastructure. An installation guide can be found [here](https://docs.ansible.com/ansible/latest/installation_guide/index.html).

Install openssh-server on the Linux machine:

```
sudo apt-get update -y
sudo apt install openssh-server -y
```

Next, add sudo/admin user with username `ansible` on both the Linux & Windows hosts.

Once this is done, modify the following variables in `ansible/inventory.ini` to match:

- ansible_password="password"
- ansible_become_password="same as above"

Ansible also requires WinRM to be configured on the Windows host, follow the guide in the [Ansible docs](https://docs.ansible.com/ansible/latest/os_guide/windows_winrm.html) to perform this.

## Installing Jenkins Server

After completing the prior step, fill in the following variables in `ansible/inventory.ini`:

- linux_host ansible_host="linux ip"
- windows_host ansible_host="windows ip"

Then from the root of the `ansible` directory, run the following command:

```
ansible-playbook -i inventory.ini main.yml -l linux
```

Once the playbook has completed, Jenkins server should be installed with necessary dependencies on the Linux host.

## Installing Jenkins Agent

Now that Jenkins is setup, it's time to setup the Jenkins agent that we'll be testing the malware on.

Go to: http://jenkins-server-ip:8080/manage/computer/new

Select type `Permanent Agent`, and under Node name write `windows`, then click `Create`.

In Labels, put `windows`. Set Remote root directory as `C:\\Jenkins` and keep the rest as default. Hit `Apply`, then `Save`.

Next go to: http://jenkins-server-ip:8080/computer/windows/

Copy the string after `-secret` in the Agent test section, and modify the following variables in `ansible/vars/main.yl` to match your setup:

- jenkins_master_url: "http://jenkins-server-ip:8080"
- jenkins_agent_secret: "generated secret"

Then from the root of the `ansible` directory, run the following command:

```
ansible-playbook -i inventory.ini main.yml -l windows
```

Once the playbook has completed, Jenkins agent should be installed with necessary dependencies on the Windows host.

## Obtaining a Deepseek API Key

DeepSeek-V3 is the model we landed on for the CI/CD pipeline as prompts involving malware development not flagging it's ethics filters. We recommend not using a reasoning model of any kind, as the price per pipeline increases substantially due to the # of tokens being generated, and it's impossible to get precise output from the model.

First create an account at: https://platform.deepseek.com/profile

Then go to: https://platform.deepseek.com/api_keys and click `Create new API Key`. Follow through the prompts and copy the displayed key to a safe location for later re-use.

Next you need to add funds to your account at: https://platform.deepseek.com/top_up

I recommend adding $2 to start, as we used $0.14 worth of tokens over the course of our testing.

## Post Installation Jenkins Server Configuration

### Setup credentials

Next, go to: http://jenkins-server-ip:8080/manage/credentials/store/system/domain/_/

Click `Add Credentials`, set Kind to `Secret text`, ID to `deepseek-api-key`, and paste the previously created API key into the Secret field.

Now we'll add an SSH key so Jenkins pipeline can authenticate to GitHub and access the repository. 

First, log into the Linux host as the jenkins user and generate an SSH key pair:

```
sudo su jenkins
ssh-keygen -t ed25519
```

Then, Click `Add Credentials`, Set Kind to `SSH Username with private key`, ID to `git-ssh`, Username to `jenkins`, and enter the private key which can be found in `/var/lib/jenkins/.ssh/id_ed25519`. Leave rest as defaults.

Jenkins pipelines also require a GitHub personal access token (PAT), so this also needs to be generated and added at https://github.com/settings/tokens.

Click `Add Credentials`, Set Kind to `Username with password`, username as your GitHub username, ID to `github-pat`, and copy and paste the generated PAT as the password.

### Configure Pipeline

Go to Jenkins Dashboard. Click `New Item`. Set item name as `Malware Pipeline`, and item type as `Multibranch Pipeline`.

Under Branch Sources, click `Add source` -> `GitHub`. Then under credentials, select `github-pat`. Fill in the repository URL.

Under Scan Repository Triggers, check `Periodically if not otherwise run`, and set the interval to 1 minute.

Click `Apply`, then `Save`

## Running the Pipeline

Modify the `LHOST` and `HOSTNAME` environment variable in the Jenkinsfile to the IP and hostname of the Jenkins server.

Then, to trigger a pipeline run, push code changes to the `staging` branch in the repository. Jenkins will scan the repo branch for changes every minute.

## Future Work

- Add re-try if fails in pipeline steps and archive errors as well as previously generated pre-build and post build scripts as artifacts which get passed to the `pipeline prebuild` and `pipeline postbuild` commands.
- Add publishing of final binaries to a GitHub release.

