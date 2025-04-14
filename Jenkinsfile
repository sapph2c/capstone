pipeline {
    agent none

    environment {
        DEEPSEEK_CREDENTIALS = credentials('deepseek-api-key')
    }

    stages {
        stage('Checkout Code') {
            agent { label 'linux' }
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: 'staging']],
                    userRemoteConfigs: [[
                        url: 'git@github.com:sapph2c/capstone.git',
                        credentialsId: 'git-ssh'
                    ]]
                ])
            }
        }

        stage('Install Python and uv') {
            agent { label 'linux' }
            steps {
                sh '''
                    sudo apt update
                    sudo apt install -y software-properties-common curl git

                    sudo add-apt-repository -y ppa:deadsnakes/ppa
                    sudo apt update
                    sudo apt install -y python3.12 python3.12-venv python3.12-dev

                    sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1

                    curl -Ls https://astral.sh/uv/install.sh | bash
                    echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
                '''
            }
        }

        stage('Generate shellcode') {
            agent { label 'linux' }
            steps {
                echo 'TODO: implement this stage'
            }
        }

        stage('Build Malware') {
            agent { label 'linux' }
            steps {
                echo 'TODO: implement this stage'
            }
        }

        stage('Execute and Detect') {
            agent { label 'windows' }
            steps {
                echo 'TODO: implement this stage'
            }
        }

        stage('Process Results') {
            agent { label 'linux' }
            steps {
                echo 'TODO: implement this stage'
            }
        }
    }
}

