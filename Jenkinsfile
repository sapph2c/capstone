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

        stage('Generate shellcode') {
            agent { label 'linux' }
            steps {
            }
        }

        stage('Build Malware') {
            agent { label 'linux' }
            steps {
                bat '''
                    echo Building malware...
                    build.bat
                '''
            }
        }

        stage('Execute and Detect') {
            agent { label 'windows' }
            steps {
                bat '''
                    echo Executing malware...
                    malware.exe || echo detected > av_detected.txt
                '''
                stash name: 'av-result', includes: 'av_detected.txt', allowEmpty: true
            }
        }

        stage('Process Results') {
            agent { label 'linux' }
            steps {
                unstash 'source'
                unstash 'av-result'
                script {
                    def avDetected = fileExists 'av_detected.txt'

                    if (avDetected) {
                        echo 'AV detected - modifying source'
                        withCredentials([string(credentialsId: 'deepseek-api-key', variable: 'DEEPSEEK_API_KEY')]) {
                            sh "python3 evasion_modifier.py --api-key $DEEPSEEK_API_KEY"
                        }
                        sh """
                            git config --global user.name "jenkins-av-evader"
                            git config --global user.email "jenkins@security.org"
                            git add .
                            git commit -m "[Automated] AV evasion attempt ${BUILD_NUMBER}"
                            git push ${env.REPO_URL} HEAD:${env.GIT_BRANCH}
                        """
                    } else {
                        echo 'Malware evaded detection - pushing to production'
                        sh """
                            git fetch origin ${env.PRODUCTION_BRANCH}
                            git checkout ${env.PRODUCTION_BRANCH}
                            git merge ${env.GIT_BRANCH} -m "Auto-merge successful evasion build ${BUILD_NUMBER}"
                            git push ${env.REPO_URL} ${env.PRODUCTION_BRANCH}
                        """
                    }
                }
            }
        }
    }
}
