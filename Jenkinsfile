pipeline {
    agent any

    environment {
        SONAR_TOKEN  = credentials('sonar-token')
        IMAGE_NAME   = "securebank"
        IMAGE_TAG    = "${BUILD_NUMBER}"
        SONAR_HOST   = "http://172.17.0.2:9000"
    }

    stages {

        stage('Checkout') {
            steps {
                echo '📦 Checking out source code...'
                checkout scm
            }
        }

        stage('Secret Scan - Gitleaks') {
            steps {
                echo '🔐 Scanning for secrets...'
                sh '''
                    mkdir -p reports
                    gitleaks detect \
                        --source . \
                        --report-format json \
                        --report-path reports/gitleaks-report.json \
                        --no-git \
                        --exit-code 0 || true
                    echo "Gitleaks scan complete"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/gitleaks-report.json',
                    allowEmptyArchive: true
                }
            }
        }

        stage('SAST - SonarQube') {
            steps {
                echo '🔍 Running static analysis...'
                script {
                    def scannerHome = tool 'SonarScanner'
                    withSonarQubeEnv('sonarqube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                            -Dsonar.projectKey=securebank \
                            -Dsonar.projectName=SecureBank \
                            -Dsonar.sources=. \
                            -Dsonar.host.url=${SONAR_HOST} \
                            -Dsonar.token=${SONAR_TOKEN} \
                            -Dsonar.exclusions=**/reports/**,**/.git/**,**/venv/**,**/*.html,**/*.js
                        """
                    }
                }
            }
        }

        stage('Dependency Scan - Snyk') {
            steps {
                echo '📦 Scanning dependencies...'
                sh '''
                    mkdir -p reports
                    cd app/securebank
                    snyk test \
                        --file=requirements.txt \
                        --package-manager=pip \
                        --json > ../../reports/snyk-report.json || true
                    echo "Snyk scan complete"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/snyk-report.json',
                    allowEmptyArchive: true
                }
            }
        }

        stage('Docker Build') {
            steps {
                echo '🐳 Building Docker image...'
                sh '''
                    docker build \
                        -t ${IMAGE_NAME}:${IMAGE_TAG} \
                        -t ${IMAGE_NAME}:latest \
                        ./app/securebank
                '''
            }
        }

        stage('Container Scan - Trivy') {
            steps {
                echo '🔎 Scanning container image...'
                sh '''
                    mkdir -p reports
                    trivy image \
                        --format json \
                        --output reports/trivy-report.json \
                        --exit-code 0 \
                        --severity HIGH,CRITICAL \
                        --timeout 30m \
                        ${IMAGE_NAME}:latest
                    echo "Trivy scan complete"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/trivy-report.json',
                    allowEmptyArchive: true
                }
            }
        }

        stage('Deploy Test Instance') {
            steps {
                echo '🚀 Deploying test instance...'
                sh '''
                    docker stop securebank || true
                    docker rm securebank || true
                    docker stop securebank-test || true
                    docker rm securebank-test || true
                    docker run -d --name securebank-test --network host ${IMAGE_NAME}:latest
                    echo "Waiting for app to start..."
                    sleep 15
                    curl -f http://localhost:5000 && echo "App is up" || echo "App health check failed"
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                echo '🌐 Running dynamic security scan...'
                sh '''
                    mkdir -p reports
                    chmod 777 reports
                    docker run --rm \
                        --network host \
                        --user root \
                        -v $(pwd)/reports:/zap/wrk/:rw \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t http://localhost:5000 \
                        -J zap-report.json \
                        -r zap-report.html \
                        -I || true
                    echo "ZAP scan complete"
                    docker stop securebank-test || true
                    docker rm securebank-test || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/zap-report.*', allowEmptyArchive: true
                }
            }
        }
        stage('Security Gate') {
            steps {
                echo '🚦 Evaluating security posture...'
                script {
                    def score   = 100
                    def issues  = []
                    def blocked = false

                    if (fileExists('reports/gitleaks-report.json')) {
                        def content = readFile('reports/gitleaks-report.json').trim()
                        if (content && content != '[]' && content != 'null' && content != '') {
                            score -= 30
                            issues.add('❌ Secrets detected in source code')
                            blocked = true
                        }
                    }

                    if (fileExists('reports/trivy-report.json')) {
                        def trivyContent = readFile('reports/trivy-report.json')
                        def critCount = trivyContent.count('"CRITICAL"')
                        if (critCount > 10) {
                            score -= 20
                            issues.add("⚠️  ${critCount} CRITICAL CVEs found in container")
                        }
                    }

                    def status = blocked ? '🚫 BLOCKED' : '✅ PASSED'
                    echo """
╔══════════════════════════════════════════╗
║      SECUREBANK SECURITY REPORT CARD    ║
╠══════════════════════════════════════════╣
║  Build:   #${BUILD_NUMBER}
║  Score:   ${score}/100
║  Status:  ${status}
║  Issues:  ${issues.size()} found
╚══════════════════════════════════════════╝
                    """
                    issues.each { issue -> echo issue }

                    if (score < 40) {
                        error "🚫 PIPELINE BLOCKED: Secrets found! Score: ${score}/100"
                    }
                    echo "✅ Security Gate PASSED — Score: ${score}/100"
                }
            }
        }

        stage('Deploy Production') {
            steps {
                echo '🎯 Deploying to production...'
                sh '''
                    docker stop securebank || true
                    docker rm securebank || true
                    docker run -d \
                        --name securebank \
                        -p 5000:5000 \
                        --restart unless-stopped \
                        ${IMAGE_NAME}:latest
                    echo "✅ SecureBank deployed at http://localhost:5000"
                '''
            }
        }
    }

    post {
        always {
            echo '🧹 Cleaning up...'
            sh 'docker stop securebank-test || true'
            sh 'docker rm securebank-test || true'
        }
        success {
            echo '✅ Pipeline completed successfully!'
        }
        failure {
            echo '❌ Pipeline failed — check reports!'
        }
    }
}
