pipeline {
    agent none
    environment {
        GITHUB_CREDS = credentials('github-pat')
        DEEPSEEK_CREDENTIALS = credentials('deepseek-api-key')
        REPO_URL = 'https://github.com/sapph2c/capstone.git'
        PRODUCTION_BRANCH = 'production'
    }
    stages {
        stage('Checkout Code') {
            agent { label 'linux' }
            steps {
                checkout scmGit(
                    branches: [[name: 'staging']],
                    userRemoteConfigs: [[url: 'https://github.com/jenkinsci/git-plugin.git']])
            }
        }

        stage('Install Python and uv') {
            agent { label 'linux' }
            steps {
                sh '''
                # Update and install prerequisites
                sudo apt update
                sudo apt install -y software-properties-common curl git

                # Add deadsnakes PPA and install Python 3.12
                sudo add-apt-repository -y ppa:deadsnakes/ppa
                sudo apt update
                sudo apt install -y python3.12 python3.12-venv python3.12-dev

                # Ensure python3.12 is available as 'python3'
                sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1

                # Install uv (Rust-based Python package manager)
                curl -Ls https://astral.sh/uv/install.sh | bash

                # Add uv to PATH for future stages
                echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
                source ~/.bashrc
                '''
            }
        }

        stage('Generate shellcode') {
            agent { label 'linux' }
            steps {
            }
        }

        stage('Build Malware') {
            agent { label 'linux' }
            steps {
            }
        }

        stage('Execute and Detect') {
            agent { label 'windows' }
            steps {
            }
        }

        stage('Process Results') {
            agent { label 'linux' }
            steps {
            }
        }
    }
}
