pipeline {
    agent none

    environment {
        DEEPSEEK_CREDENTIALS = credentials('deepseek-api-key')
        LHOST = '100.85.95.64'
        LPORT = 4444
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

